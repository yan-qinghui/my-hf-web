from fastapi import FastAPI, Request
from fastapi.responses import Response, HTMLResponse
from huggingface_hub import HfApi, HfFileSystem
import os
import base64
from xml.etree import ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlparse
import mimetypes

class HuggingFaceWebDAV:
    def __init__(self, username, dataset, token):
        self.username = username
        self.dataset = dataset
        self.dataset_id = f"{username}/{dataset}"
        self.token = token
        self.api = HfApi(token=token)
        self.fs = HfFileSystem(token=token)

    def _encode_path(self, path, safe_chars=''):
        """
        正确编码路径，处理中文和特殊字符
        参考 Go 版本的 utils.EncodePath 实现
        """
        if not path:
            return path
        # 对路径的每个部分分别编码，保留路径分隔符
        parts = path.split('/')
        encoded_parts = []
        for part in parts:
            if part:  # 跳过空字符串（由连续的 / 产生）
                # 编码每个路径段，但保留一些安全字符
                encoded_part = quote(part, safe=safe_chars)
                encoded_parts.append(encoded_part)
            else:
                encoded_parts.append(part)
        return '/'.join(encoded_parts)

    def _decode_path(self, path):
        """解码路径"""
        return unquote(path) if path else path

    def _validate_path(self, path):
        """验证路径安全性，防止路径遍历攻击"""
        if not path:
            return True

        # 检查是否包含危险的路径组件
        dangerous_patterns = ['..', '\\', '\x00']
        for pattern in dangerous_patterns:
            if pattern in path:
                return False

        # 检查是否为绝对路径（应该是相对路径）
        if os.path.isabs(path):
            return False

        return True

    def _format_time(self, t):
        if isinstance(t, str):
            try:
                t = datetime.fromisoformat(t.replace("Z", "+00:00"))
            except Exception:
                t = datetime.now(timezone.utc)
        return t.strftime("%a, %d %b %Y %H:%M:%S GMT")

    def _ensure_parent_dirs(self, path):
        # 自动为文件创建父目录（带.keep），保证目录能及时显示
        parts = path.strip('/').split('/')[:-1]
        repo_path = f"datasets/{self.dataset_id}"
        for i in range(1, len(parts)+1):
            dir_path = '/'.join(parts[:i])
            keep_file = f"{repo_path}/{dir_path}/.keep"
            if not self.fs.exists(keep_file):
                with self.fs.open(keep_file, 'wb') as f:
                    f.write(b"")

    def _invalidate_cache(self, path):
        # 强制刷新fsspec缓存，确保ls能获取到最新内容
        if hasattr(self.fs, 'invalidate_cache'):
            self.fs.invalidate_cache(path)
        if hasattr(self.fs, 'clear_instance_cache'):
            self.fs.clear_instance_cache()
        # 也可以尝试重建fs对象
        # self.fs = HfFileSystem(token=self.token)

    async def handle_propfind(self, path: str = "/") -> Response:
        try:
            # 解码传入的路径，处理中文和特殊字符
            decoded_path = self._decode_path(path.strip('/'))

            # 验证路径安全性
            if not self._validate_path(decoded_path):
                return Response(status_code=400, content="Invalid path")

            repo_path = f"datasets/{self.dataset_id}"
            current_path = f"{repo_path}/{decoded_path}" if decoded_path else repo_path

            # 强制刷新缓存，确保目录内容最新
            self._invalidate_cache(current_path)

            files_info = self.fs.ls(current_path, detail=True)
            directories = set()
            files_in_current_dir = {}

            for file_info in files_info:
                full_path = file_info['name']
                rel_path = full_path[len(repo_path):].strip('/')
                if not rel_path:
                    continue
                if file_info['type'] == 'directory':
                    directories.add(rel_path)
                else:
                    if os.path.basename(rel_path) == ".keep":
                        continue
                    last_modified = file_info.get('last_modified')
                    if last_modified:
                        last_modified = self._format_time(last_modified)
                    else:
                        last_modified = self._format_time(datetime.now(timezone.utc))
                    files_in_current_dir[rel_path] = {
                        'size': file_info.get('size', 0),
                        'last_modified': last_modified
                    }

            root = ET.Element("{DAV:}multistatus", {"xmlns:D": "DAV:"})

            # 当前目录
            response_elem = ET.SubElement(root, "{DAV:}response")
            # 正确编码 href，参考 Go 版本的 EscapedPath()
            current_href = f"/{self._encode_path(decoded_path)}" if decoded_path else "/"
            ET.SubElement(response_elem, "{DAV:}href").text = current_href
            propstat = ET.SubElement(response_elem, "{DAV:}propstat")
            prop = ET.SubElement(propstat, "{DAV:}prop")
            resourcetype = ET.SubElement(prop, "{DAV:}resourcetype")
            ET.SubElement(resourcetype, "{DAV:}collection")
            ET.SubElement(prop, "{DAV:}displayname").text = os.path.basename(decoded_path) if decoded_path else "/"
            ET.SubElement(prop, "{DAV:}getlastmodified").text = self._format_time(datetime.now(timezone.utc))
            ET.SubElement(propstat, "{DAV:}status").text = "HTTP/1.1 200 OK"

            # 目录
            for directory in sorted(directories):
                response_elem = ET.SubElement(root, "{DAV:}response")
                # 正确编码目录路径
                encoded_dir = self._encode_path(directory)
                ET.SubElement(response_elem, "{DAV:}href").text = f"/{encoded_dir}/"
                propstat = ET.SubElement(response_elem, "{DAV:}propstat")
                prop = ET.SubElement(propstat, "{DAV:}prop")
                resourcetype = ET.SubElement(prop, "{DAV:}resourcetype")
                ET.SubElement(resourcetype, "{DAV:}collection")
                ET.SubElement(prop, "{DAV:}getcontenttype").text = "httpd/unix-directory"
                ET.SubElement(prop, "{DAV:}displayname").text = os.path.basename(directory)
                ET.SubElement(prop, "{DAV:}getlastmodified").text = self._format_time(datetime.now(timezone.utc))
                ET.SubElement(propstat, "{DAV:}status").text = "HTTP/1.1 200 OK"

            # 文件
            for file, info in sorted(files_in_current_dir.items()):
                response_elem = ET.SubElement(root, "{DAV:}response")
                # 正确编码文件路径
                encoded_file = self._encode_path(file)
                ET.SubElement(response_elem, "{DAV:}href").text = f"/{encoded_file}"
                propstat = ET.SubElement(response_elem, "{DAV:}propstat")
                prop = ET.SubElement(propstat, "{DAV:}prop")
                ET.SubElement(prop, "{DAV:}resourcetype")
                ET.SubElement(prop, "{DAV:}getcontenttype").text = "application/octet-stream"
                ET.SubElement(prop, "{DAV:}getcontentlength").text = str(info['size'])
                ET.SubElement(prop, "{DAV:}getlastmodified").text = info['last_modified']
                ET.SubElement(prop, "{DAV:}displayname").text = os.path.basename(file)
                ET.SubElement(propstat, "{DAV:}status").text = "HTTP/1.1 200 OK"

            xml_str = '<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(root, encoding='unicode')
            return Response(
                content=xml_str,
                media_type="application/xml; charset=utf-8",
                status_code=207,
                headers={
                    "DAV": "1,2",
                    "MS-Author-Via": "DAV",
                    "Cache-Control": "no-cache",
                    "Content-Type": "application/xml; charset=utf-8"
                }
            )
        except Exception as e:
            print(f"PROPFIND error: {str(e)}")
            return Response(status_code=500)

    async def handle_get(self, path: str) -> Response:
        try:
            # 解码路径，处理中文和特殊字符
            decoded_path = self._decode_path(path.strip('/'))

            # 验证路径安全性
            if not self._validate_path(decoded_path):
                return Response(status_code=400, content="Invalid path")

            repo_path = f"datasets/{self.dataset_id}/{decoded_path}"

            with self.fs.open(repo_path, 'rb') as f:
                content = f.read()

            # 根据文件扩展名确定 MIME 类型
            content_type, _ = mimetypes.guess_type(decoded_path)
            if not content_type:
                content_type = "application/octet-stream"

            # 正确编码文件名用于下载
            filename = os.path.basename(decoded_path)
            encoded_filename = quote(filename)

            return Response(
                content=content,
                media_type=content_type,
                headers={
                    "Content-Disposition": f'attachment; filename*=UTF-8\'\'{encoded_filename}',
                    "Accept-Ranges": "bytes",
                    "Content-Length": str(len(content))
                }
            )
        except Exception as e:
            print(f"GET error: {str(e)}")
            return Response(status_code=404)

    async def handle_head(self, path: str) -> Response:
        """处理 HEAD 请求，返回文件信息但不返回内容"""
        try:
            # 解码路径，处理中文和特殊字符
            decoded_path = self._decode_path(path.strip('/'))

            # 验证路径安全性
            if not self._validate_path(decoded_path):
                return Response(status_code=400, content="Invalid path")

            repo_path = f"datasets/{self.dataset_id}/{decoded_path}"

            # 获取文件信息但不读取内容
            file_info = self.fs.info(repo_path)

            # 根据文件扩展名确定 MIME 类型
            content_type, _ = mimetypes.guess_type(decoded_path)
            if not content_type:
                content_type = "application/octet-stream"

            # 正确编码文件名用于下载
            filename = os.path.basename(decoded_path)
            encoded_filename = quote(filename)

            return Response(
                status_code=200,
                headers={
                    "Content-Type": content_type,
                    "Content-Length": str(file_info.get('size', 0)),
                    "Content-Disposition": f'attachment; filename*=UTF-8\'\'{encoded_filename}',
                    "Accept-Ranges": "bytes",
                    "Last-Modified": self._format_time(file_info.get('last_modified', datetime.now(timezone.utc)))
                }
            )
        except Exception as e:
            print(f"HEAD error: {str(e)}")
            return Response(status_code=404)

    async def handle_put(self, path: str, content: bytes) -> Response:
        try:
            # 解码路径，处理中文和特殊字符
            decoded_path = self._decode_path(path.strip('/'))

            # 验证路径安全性
            if not self._validate_path(decoded_path):
                return Response(status_code=400, content="Invalid path")

            # 自动创建父目录（带.keep），保证目录能及时显示
            self._ensure_parent_dirs(decoded_path)
            repo_path = f"datasets/{self.dataset_id}/{decoded_path}"

            with self.fs.open(repo_path, 'wb') as f:
                f.write(content)

            # 上传后刷新缓存，确保目录能及时看到新文件
            parent_dir = os.path.dirname(repo_path)
            self._invalidate_cache(parent_dir)
            return Response(status_code=201)
        except Exception as e:
            print(f"PUT error: {str(e)}")
            return Response(status_code=500)

    async def handle_mkcol(self, path: str) -> Response:
        try:
            # 解码路径，处理中文和特殊字符
            decoded_path = self._decode_path(path.strip('/'))
            repo_path = f"datasets/{self.dataset_id}/{decoded_path}/.keep"

            with self.fs.open(repo_path, 'wb') as f:
                f.write(b"")

            parent_dir = os.path.dirname(os.path.dirname(repo_path))
            self._invalidate_cache(parent_dir)
            return Response(status_code=201)
        except Exception as e:
            print(f"MKCOL error: {str(e)}")
            return Response(status_code=500)

    def _recursive_delete(self, repo_path):
        # 递归删除目录下所有文件和子目录
        if self.fs.exists(repo_path):
            if self.fs.isdir(repo_path):
                files = self.fs.ls(repo_path, detail=True)
                for file in files:
                    self._recursive_delete(file['name'])
                # 删除目录下的.keep文件
                keep_file = os.path.join(repo_path, ".keep")
                if self.fs.exists(keep_file):
                    self.fs.delete(keep_file)
            else:
                self.fs.delete(repo_path)

    async def handle_delete(self, path: str) -> Response:
        try:
            # 解码路径，处理中文和特殊字符
            decoded_path = self._decode_path(path.strip('/'))
            repo_path = f"datasets/{self.dataset_id}/{decoded_path}"

            self._recursive_delete(repo_path)
            parent_dir = os.path.dirname(repo_path)
            self._invalidate_cache(parent_dir)
            return Response(status_code=204)
        except Exception as e:
            print(f"DELETE error: {str(e)}")
            return Response(status_code=500)

    async def handle_move(self, source: str, destination: str) -> Response:
        try:
            # 解码路径，处理中文和特殊字符
            decoded_src = self._decode_path(source.strip('/'))
            decoded_dst = self._decode_path(destination.strip('/'))

            src_path = f"datasets/{self.dataset_id}/{decoded_src}"
            dst_path = f"datasets/{self.dataset_id}/{decoded_dst}"

            with self.fs.open(src_path, 'rb') as src:
                content = src.read()

            self._ensure_parent_dirs(decoded_dst)
            with self.fs.open(dst_path, 'wb') as dst:
                dst.write(content)

            self.fs.delete(src_path)
            self._invalidate_cache(os.path.dirname(src_path))
            self._invalidate_cache(os.path.dirname(dst_path))
            return Response(status_code=201)
        except Exception as e:
            print(f"MOVE error: {str(e)}")
            return Response(status_code=500)

    async def handle_copy(self, source: str, destination: str) -> Response:
        try:
            # 解码路径，处理中文和特殊字符
            decoded_src = self._decode_path(source.strip('/'))
            decoded_dst = self._decode_path(destination.strip('/'))

            src_path = f"datasets/{self.dataset_id}/{decoded_src}"
            dst_path = f"datasets/{self.dataset_id}/{decoded_dst}"

            with self.fs.open(src_path, 'rb') as src:
                content = src.read()

            self._ensure_parent_dirs(decoded_dst)
            with self.fs.open(dst_path, 'wb') as dst:
                dst.write(content)

            self._invalidate_cache(os.path.dirname(dst_path))
            return Response(status_code=201)
        except Exception as e:
            print(f"COPY error: {str(e)}")
            return Response(status_code=500)

app = FastAPI()

@app.get("/")
async def root():
    return HTMLResponse("""
    <html>
    <head>
        <title>NextChat - AI Chat Web App</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                margin: 0;
                padding: 0;
                height: 100vh;
                display: flex;
                flex-direction: column;
            }
            iframe {
                flex-grow: 1;
                width: 100%;
                height: 100%;
                border: none;
            }
        </style>
    </head>
    <body>
        <iframe src="https://app.nextchat.dev/" frameborder="0" allowfullscreen></iframe>
    </body>
    </html>
    """)

@app.api_route("/{path:path}", methods=["GET", "HEAD", "PUT", "PROPFIND", "MKCOL", "DELETE", "COPY", "MOVE", "OPTIONS"])
async def handle_webdav(request: Request, path: str = ""):
    if request.method == "OPTIONS":
        return Response(
            headers={
                "Allow": "GET, HEAD, PUT, PROPFIND, PROPPATCH, MKCOL, DELETE, COPY, MOVE, LOCK, UNLOCK, OPTIONS",
                "DAV": "1, 2",
                "MS-Author-Via": "DAV",
                "Accept-Ranges": "bytes",
                "Cache-Control": "no-cache"
            }
        )

    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Basic "):
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="HuggingFace WebDAV"'}
        )

    try:
        auth_decoded = base64.b64decode(auth[6:]).decode()
        username_dataset, token = auth_decoded.split(":")
        username, dataset = username_dataset.split("/")
        webdav = HuggingFaceWebDAV(username, dataset, token)

        if request.method == "PROPFIND":
            return await webdav.handle_propfind(path)
        elif request.method == "GET":
            return await webdav.handle_get(path)
        elif request.method == "HEAD":
            return await webdav.handle_head(path)
        elif request.method == "PUT":
            content = await request.body()
            return await webdav.handle_put(path, content)
        elif request.method == "MKCOL":
            return await webdav.handle_mkcol(path)
        elif request.method == "DELETE":
            return await webdav.handle_delete(path)
        elif request.method == "MOVE":
            destination = request.headers.get("Destination", "")
            if not destination:
                return Response(status_code=400)
            # 正确解析 Destination URL，处理编码的路径
            parsed_dest = urlparse(destination)
            destination_path = parsed_dest.path.split("/", 3)[-1] if len(parsed_dest.path.split("/")) > 3 else parsed_dest.path.lstrip("/")
            return await webdav.handle_move(path, destination_path)
        elif request.method == "COPY":
            destination = request.headers.get("Destination", "")
            if not destination:
                return Response(status_code=400)
            # 正确解析 Destination URL，处理编码的路径
            parsed_dest = urlparse(destination)
            destination_path = parsed_dest.path.split("/", 3)[-1] if len(parsed_dest.path.split("/")) > 3 else parsed_dest.path.lstrip("/")
            return await webdav.handle_copy(path, destination_path)
        else:
            return Response(status_code=405)
    except Exception as e:
        print(f"Error: {str(e)}")
        return Response(status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)

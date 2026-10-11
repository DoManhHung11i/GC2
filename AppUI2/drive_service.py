"""Google Drive API operations."""
import io
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

from auth_manager import creds_for, active_email


def _svc(email=None):
    email = email or active_email()
    return build("drive", "v3", credentials=creds_for(email), cache_discovery=False)


def drive_list(folder_id: str, email=None):
    resp = _svc(email).files().list(
        q=f"'{folder_id}' in parents and trashed=false",
        fields="files(id,name,size,mimeType,modifiedTime)",
        supportsAllDrives=True,
        includeItemsFromAllDrives=True,
        orderBy="modifiedTime desc",
    ).execute()
    return resp.get("files", [])


def drive_download(file_id: str, email=None) -> bytes:
    req = _svc(email).files().get_media(fileId=file_id, supportsAllDrives=True)
    buf = io.BytesIO()
    dl = MediaIoBaseDownload(buf, req)
    done = False
    while not done:
        _, done = dl.next_chunk()
    return buf.getvalue()


def drive_upload(folder_id: str, data: bytes, filename: str, email=None) -> str:
    media = MediaIoBaseUpload(io.BytesIO(data),
                              mimetype="application/octet-stream",
                              resumable=False)
    f = _svc(email).files().create(
        body={"name": filename, "parents": [folder_id]},
        media_body=media, fields="id", supportsAllDrives=True,
    ).execute()
    return f["id"]


def drive_delete(file_id: str, email=None):
    _svc(email).files().delete(fileId=file_id, supportsAllDrives=True).execute()

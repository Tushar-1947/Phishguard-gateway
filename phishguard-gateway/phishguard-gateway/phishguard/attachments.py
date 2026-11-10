"""Attachment inspection: dangerous types, double extensions, macros, hashes."""
import hashlib
import os
from typing import List, Tuple

from .models import Finding

EXECUTABLE = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
              ".wsf", ".hta", ".jar", ".msi", ".lnk", ".reg", ".dll", ".iso", ".img"}
MACRO = {".docm", ".xlsm", ".pptm", ".dotm", ".xlsb"}
ARCHIVE = {".zip", ".rar", ".7z", ".gz", ".tar", ".cab"}
DOC_LIKE = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png", ".ppt", ".pptx"}


def analyze_attachments(msg) -> Tuple[List[dict], List[Finding]]:
    info: List[dict] = []
    f: List[Finding] = []
    for part in msg.walk():
        name = part.get_filename()
        if not name:
            continue
        payload = part.get_payload(decode=True) or b""
        base = os.path.basename(name).lower()
        root, ext = os.path.splitext(base)
        info.append({"filename": name, "size": len(payload),
                     "sha256": hashlib.sha256(payload).hexdigest(),
                     "content_type": part.get_content_type()})
        inner_ext = os.path.splitext(root)[1]
        if ext in EXECUTABLE:
            f.append(Finding("attachment", f"Executable/script attachment: {name}", 35))
        if inner_ext in DOC_LIKE and ext in EXECUTABLE:
            f.append(Finding("attachment", f"Double extension disguises executable: {name}", 20))
        if ext in MACRO:
            f.append(Finding("attachment", f"Macro-enabled Office file: {name}", 20))
        if ext in ARCHIVE:
            f.append(Finding("attachment", f"Archive attachment (may hide payload): {name}", 6))
        if len(base) != len(base.strip()) or "\u202e" in name:
            f.append(Finding("attachment", f"Filename uses RTL-override/whitespace trick: {name!r}", 25))
    return info, f

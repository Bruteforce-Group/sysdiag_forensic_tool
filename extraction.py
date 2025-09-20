#!/usr/bin/env python3
import tarfile, tempfile, os

def extract_sysdiagnose(archive_path: str) -> str:
    """
    Extract a sysdiagnose .tar.gz archive to a temp dir and return its path.
    """
    if not os.path.isfile(archive_path):
        raise FileNotFoundError(f"Archive not found: {archive_path}")
    workdir = tempfile.mkdtemp(prefix='sysdiag_')
    with tarfile.open(archive_path, 'r:gz') as tf:
        tf.extractall(workdir)
    return workdir

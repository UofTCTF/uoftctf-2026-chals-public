import hashlib
import io
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import numpy as np
from PIL import Image

from config import Config


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def load_gray_from_bytes(data: bytes) -> Image.Image:
    with Image.open(io.BytesIO(data)) as img:
        return img.convert("L")


def image_to_uint8(img: Image.Image) -> np.ndarray:
    arr = np.asarray(img, dtype=np.uint8)
    if arr.ndim == 2:
        return arr
    if arr.ndim == 3 and arr.shape[2] in (1, 3):
        return arr
    raise ValueError("image must be L or RGB")


def pixel_diff(a: np.ndarray, b: np.ndarray) -> int:
    if a.shape != b.shape:
        raise ValueError("shape mismatch")
    if a.ndim == 2:
        diff = a != b
    else:
        diff = np.any(a != b, axis=2)
    return int(np.count_nonzero(diff))


@dataclass
class Verifier:
    config: Config
    predict_fn: Callable

    def expected_filenames(self) -> list:
        names = []
        for i in range(10):
            names.append(f"pair_{i:02d}_img1.png")
            names.append(f"pair_{i:02d}_img2.png")
        return names

    def verify_zip(self, zip_bytes: bytes) -> bool:
        refs_dir = Path(__file__).resolve().parent / "data" / "refs"

        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            entries = zf.namelist()
            if not entries:
                return False

            expected = set(self.expected_filenames())
            if set(entries) != expected:
                return False

            for i in range(10):
                ref_path = refs_dir / f"ref_{i:02d}.png"
                if not ref_path.exists():
                    return False

                ref_img = Image.open(ref_path).convert("L")
                ref_arr = image_to_uint8(ref_img)

                img1_name = f"pair_{i:02d}_img1.png"
                img2_name = f"pair_{i:02d}_img2.png"

                img1_bytes = zf.read(img1_name)
                img2_bytes = zf.read(img2_name)

                try:
                    img1 = load_gray_from_bytes(img1_bytes)
                    img2 = load_gray_from_bytes(img2_bytes)
                except Exception:
                    return False

                img1_arr = image_to_uint8(img1)
                img2_arr = image_to_uint8(img2)

                if img1_arr.shape != ref_arr.shape:
                    return False
                if pixel_diff(ref_arr, img1_arr) != 0:
                    return False

                if img2_arr.shape != ref_arr.shape:
                    return False
                diff_img2_img1 = pixel_diff(ref_arr, img2_arr)
                budget = int(self.config.budgets[i])
                if diff_img2_img1 > budget:
                    return False

                if md5_hex(img1_bytes) != md5_hex(img2_bytes):
                    return False

                try:
                    img1_top1 = self.predict_fn(img1)
                    if img1_top1["id"] != self.config.reference_class_ids[i]:
                        return False
                except Exception:
                    return False

                try:
                    img2_top1 = self.predict_fn(img2)
                    target_id = int(self.config.target_class_ids[i])
                    if img2_top1["id"] != target_id:
                        return False
                except Exception:
                    return False

        return True

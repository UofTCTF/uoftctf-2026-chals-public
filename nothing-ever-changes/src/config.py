from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Config:
    target_class_id: int | None
    target_class_ids: list | None
    reference_class_ids: list
    budgets: list | None
    max_upload_mb: int
    flag: str


def load_config() -> Config:
    target_class_ids = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1]
    reference_class_ids = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    budgets = [55, 30, 30, 65, 30, 10, 55, 40, 40, 40]
    max_upload_mb = 20
    flag = "uoftctf{d1d_y0u_kn0w_4_UofT_pr0f3550r_m4d3_th3_JSMA_p4p3r(https://doi.org/10.48550/arXiv.1511.07528)???}"

    return Config(
        target_class_id=None,
        target_class_ids=target_class_ids,
        reference_class_ids=reference_class_ids,
        budgets=budgets,
        max_upload_mb=max_upload_mb,
        flag=flag,
    )

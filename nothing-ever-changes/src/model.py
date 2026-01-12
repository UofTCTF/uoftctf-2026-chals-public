import random
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Callable

import numpy as np
import torch
import torch.nn as nn
from PIL import Image
from torchvision.transforms import functional as TF


MNIST_MEAN = 0.1307
MNIST_STD = 0.3081


class MnistNet(nn.Module):
    def __init__(self) -> None:
        super().__init__()
        self.conv1 = nn.Conv2d(1, 32, kernel_size=3, padding=1)
        self.conv2 = nn.Conv2d(32, 64, kernel_size=3, padding=1)
        self.fc1 = nn.Linear(64 * 7 * 7, 128)
        self.fc2 = nn.Linear(128, 10)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = torch.relu(self.conv1(x))
        x = torch.max_pool2d(x, 2)
        x = torch.relu(self.conv2(x))
        x = torch.max_pool2d(x, 2)
        x = x.view(x.size(0), -1)
        x = torch.relu(self.fc1(x))
        return self.fc2(x)


@dataclass(frozen=True)
class ModelBundle:
    model: torch.nn.Module
    categories: list
    preprocess_pil: Callable[[Image.Image], torch.Tensor]
    preprocess_tensor: Callable[[torch.Tensor], torch.Tensor]


def set_deterministic(seed: int = 0) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def _to_grayscale_tensor(x: torch.Tensor) -> torch.Tensor:
    if x.shape[1] == 1:
        return x
    if x.shape[1] != 3:
        raise ValueError("expected 1 or 3 channels")
    r, g, b = x[:, 0:1], x[:, 1:2], x[:, 2:3]
    return 0.2989 * r + 0.5870 * g + 0.1140 * b


def _preprocess_tensor(x: torch.Tensor) -> torch.Tensor:
    x = _to_grayscale_tensor(x)
    x = TF.resize(x, [28, 28], antialias=True)
    x = TF.center_crop(x, [28, 28])
    mean = torch.tensor([MNIST_MEAN], device=x.device).view(1, 1, 1, 1)
    std = torch.tensor([MNIST_STD], device=x.device).view(1, 1, 1, 1)
    return (x - mean) / std


def _preprocess_pil(img: Image.Image) -> torch.Tensor:
    if img.mode != "L":
        img = img.convert("L")
    x = TF.to_tensor(img).unsqueeze(0)
    return _preprocess_tensor(x).squeeze(0)


def _build_bundle(device: str = "cpu") -> ModelBundle:
    model = MnistNet()
    model.eval()
    model.to(device)
    weights_path = Path(__file__).resolve().parent / "mnist_cnn.pth"
    if weights_path.exists():
        state = torch.load(weights_path, map_location=device)
        model.load_state_dict(state)
    categories = [str(i) for i in range(10)]
    return ModelBundle(
        model=model,
        categories=categories,
        preprocess_pil=_preprocess_pil,
        preprocess_tensor=_preprocess_tensor,
    )


@lru_cache(maxsize=1)
def get_model_bundle(device: str = "cpu") -> ModelBundle:
    return _build_bundle(device=device)


def predict_top1(image: Image.Image, bundle: ModelBundle) -> dict:
    x = bundle.preprocess_pil(image).unsqueeze(0)
    with torch.no_grad():
        logits = bundle.model(x)
        probs = torch.softmax(logits, dim=1)[0]
    top1 = int(torch.argmax(probs).item())
    return {
        "id": top1,
        "label": bundle.categories[top1],
        "prob": float(probs[top1].item()),
    }

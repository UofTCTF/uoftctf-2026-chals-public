def __s(a, k=42):
    return bytes([x ^ k for x in a]).decode('utf-8')

def __gi(m, n):
    try:
        return getattr(importlib.import_module(m), n)
    except AttributeError:
        return importlib.import_module(m + __s([4]) + n)

def __bi(n):
    b = __builtins__
    if isinstance(b, dict):
        return b[n]
    else:
        try:
            return getattr(b, n)
        except Exception:
            return getattr(__import__(__s([72, 95, 67, 70, 94, 67, 68, 89])), n)
import importlib
sys = getattr(importlib, __s([67, 71, 90, 69, 88, 94, 117, 71, 69, 78, 95, 70, 79]))(__s([89, 83, 89]))
Path = __gi(__s([90, 75, 94, 66, 70, 67, 72]), __s([122, 75, 94, 66]))
importlib = getattr(importlib, __s([67, 71, 90, 69, 88, 94, 117, 71, 69, 78, 95, 70, 79]))(__s([67, 71, 90, 69, 88, 94, 70, 67, 72]))
np = getattr(importlib, __s([67, 71, 90, 69, 88, 94, 117, 71, 69, 78, 95, 70, 79]))(__s([68, 95, 71, 90, 83]))
torch = getattr(importlib, __s([67, 71, 90, 69, 88, 94, 117, 71, 69, 78, 95, 70, 79]))(__s([94, 69, 88, 73, 66]))
Image = __gi(__s([122, 99, 102]), __s([99, 71, 75, 77, 79]))
model_obf = getattr(importlib, __s([67, 71, 90, 69, 88, 94, 117, 71, 69, 78, 95, 70, 79]))(__s([71, 69, 78, 79, 70]))

def v39194d9e8c3d1b19(vc91053b95402ebe9):
    v17218b28ce899876 = getattr(getattr(Image, __s([69, 90, 79, 68]))(vc91053b95402ebe9), __s([73, 69, 68, 92, 79, 88, 94]))(__s([120, 109, 104]))
    v17218b28ce899876 = getattr(v17218b28ce899876, __s([88, 79, 89, 67, 80, 79]))((256, 256), getattr(Image, __s([104, 99, 102, 99, 100, 111, 107, 120])))
    ve0645baf54c29996 = getattr(np, __s([75, 88, 88, 75, 83]))(v17218b28ce899876, dtype=getattr(np, __s([76, 70, 69, 75, 94, 25, 24]))) / 255.0
    vbd7b635d263f1636 = getattr(getattr(getattr(torch, __s([76, 88, 69, 71, 117, 68, 95, 71, 90, 83]))(ve0645baf54c29996), __s([90, 79, 88, 71, 95, 94, 79]))(2, 0, 1), __s([73, 69, 68, 94, 67, 77, 95, 69, 95, 89]))()
    return getattr(vbd7b635d263f1636, __s([95, 68, 89, 91, 95, 79, 79, 80, 79]))(0)

def v8b76886d9d2f9cdb():
    if len(getattr(sys, __s([75, 88, 77, 92]))) != 2:
        __bi(__s([90, 88, 67, 68, 94]))(__s([26]))
        return
    vc91053b95402ebe9 = Path(getattr(sys, __s([75, 88, 77, 92]))[1])
    if not getattr(vc91053b95402ebe9, __s([79, 82, 67, 89, 94, 89]))():
        __bi(__s([90, 88, 67, 68, 94]))(__s([26]))
        return
    v40a367d63d330ff6 = None
    for v8d0d01a984bbbf45 in getattr(getattr(model_obf, __s([117, 117, 78, 67, 73, 94, 117, 117])), __s([92, 75, 70, 95, 79, 89]))():
        if isinstance(v8d0d01a984bbbf45, type) and hasattr(v8d0d01a984bbbf45, __s([117, 117, 79, 68, 94, 88, 83, 117, 117])) and (getattr(v8d0d01a984bbbf45, __s([117, 117, 79, 68, 94, 88, 83, 117, 117])) is True):
            v40a367d63d330ff6 = v8d0d01a984bbbf45
            break
    if v40a367d63d330ff6 is None:
        __bi(__s([90, 88, 67, 68, 94]))(__s([26]))
        return
    v3383be8681d35a0d = v40a367d63d330ff6()
    v9609c5bc5448ef37 = getattr(torch, __s([70, 69, 75, 78]))(getattr(Path(__file__), __s([90, 75, 88, 79, 68, 94])) / __s([93, 79, 67, 77, 66, 94, 89, 4, 90, 94]), map_location=__s([73, 90, 95]))
    getattr(v3383be8681d35a0d, __s([70, 69, 75, 78, 117, 89, 94, 75, 94, 79, 117, 78, 67, 73, 94]))(v9609c5bc5448ef37)
    getattr(v3383be8681d35a0d, __s([79, 92, 75, 70]))()
    vbd7b635d263f1636 = v39194d9e8c3d1b19(vc91053b95402ebe9)
    with getattr(torch, __s([68, 69, 117, 77, 88, 75, 78]))():
        vc2ab17f16a2b2123 = v3383be8681d35a0d(vbd7b635d263f1636)
    if int(getattr(vc2ab17f16a2b2123, __s([67, 94, 79, 71]))()) > 9:
        __bi(__s([90, 88, 67, 68, 94]))(__s([83, 69, 95, 10, 77, 69, 94, 10, 67, 94, 11]))
    else:
        __bi(__s([90, 88, 67, 68, 94]))(int(getattr(vc2ab17f16a2b2123, __s([67, 94, 79, 71]))()))
if __name__ == __s([117, 117, 71, 75, 67, 68, 117, 117]):
    v8b76886d9d2f9cdb()

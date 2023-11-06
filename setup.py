from distutils.core import setup
from Cython.Build import cythonize
setup(
name = "SM3_test",
ext_modules = cythonize("SM3_test.py"), #将test.py文件编译成pyd
)
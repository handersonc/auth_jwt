from setuptools import setup

setup(name='auth_jwt',
      version='0.1.3',
      description='Module to give secure the api with jwt token',
      url='https://github.com/handerson2014/auth_jwt.git',
      author='Handerson Contreras',
      author_email='handerson.contreras@gmail.com',
      license='MIT',
      packages=['auth_jwt'],
      install_requires=['PyJWT'],
      zip_safe=False)

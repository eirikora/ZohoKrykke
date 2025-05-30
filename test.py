import openai, sys, pathlib
print("Python:", sys.version)
print("openai versjon:", openai.__version__)
print("openai ligger i:", pathlib.Path(openai.__file__).parent)


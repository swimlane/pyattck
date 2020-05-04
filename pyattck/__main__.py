import fire

from pyattck import Attck


def main(args=None):
    attck = Attck()
    fire.Fire(attck)

if __name__ == "__main__":
    main()
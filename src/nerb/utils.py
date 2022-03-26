from __future__ import annotations

# Standard library
from pathlib import Path

# Third-party
import yaml


__all__ = ['load_yaml_config']


def load_yaml_config(file_path: str | Path) -> dict:
    """

    Parameters
    ----------
    file_path : str or Path
        Yaml config file name. The file is assumed to be in
        the repo's config directory.

    Returns
    -------
    config : dict
        Configuration parameters stored in a dictionary.
    """
    file_path = Path(file_path)

    with open(file_path) as file:
        config = yaml.load(file, Loader=yaml.CLoader)
    return config

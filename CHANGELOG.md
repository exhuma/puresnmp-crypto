# v1.0.1 - Maintenance release

This release only contains internal changes. Nothing on the external API has
been modified.

`pycrypto` has been replaced with `cryptography` as `pycrypto` is no longer
maintained and caused issues with Python 3.10.

Additionally, this release switches back from `poetry` to `setuptools` for
project packaging. `poetry` did not bring any substantial "added value" while
diverging from the pypa standards with some keys and making the build slower.


# v1.0.0 - Initial Release

No changes

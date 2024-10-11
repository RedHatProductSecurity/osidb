from .source import FlawSource

# unfortunatelly adding Flaw or any of its children here
# creates import cycle and I do not see an easy way around
__all__ = ("FlawSource",)

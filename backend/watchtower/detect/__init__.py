"""Detection.

``rules`` is what the live dashboard runs. ``parser`` and ``features`` build the
representation the benchmarked model is trained on. Keeping them in one package
with separate modules is deliberate: they are both detection, and the API is
explicit about which one produced any given verdict.
"""

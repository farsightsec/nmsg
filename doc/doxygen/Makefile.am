EXTRA_DIST = doxygen-input-filter

html: Doxyfile doxygen-input-filter
	doxygen

clean-local:
	-rm -rf html doxygen.warnings

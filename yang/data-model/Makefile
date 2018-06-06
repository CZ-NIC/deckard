MODULES = cznic-resolver-common cznic-deckard
# Paths for pyang
xsldir = ../../yangson/tools/xslt
yams = $(addsuffix .yang, $(MODULES))

.PHONY: all

all: $(yams)

%.yang: %.yinx
	@xsltproc --xinclude $(xsldir)/canonicalize.xsl $< | \
	  xsltproc --output $@ $(yypars) $(xsldir)/yin2yang.xsl -



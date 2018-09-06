MODULES = cznic-resolver-common cznic-resolver-knot cznic-deckard
DATE ?= $(shell date +%F)

xsldir = ../../yangson/tools/xslt
yypars = --stringparam date $(DATE)
yams = $(addsuffix .yang, $(MODULES))

.PHONY: all

all: $(yams)

%.yang: %.yinx
	@xsltproc --xinclude $(xsldir)/canonicalize.xsl $< | \
	  xsltproc --output $@ $(yypars) $(xsldir)/yin2yang.xsl -

model.tree: $(yams)
	@pyang $(PYANG_OPTS) -f tree -o $@ $^

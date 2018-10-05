all: fileserver

BUILD=static

#
# css
#
CSS_C=sass
CSS_FLAGS=
CSS_SRC=data
SCSS_INCLUDES=$(CSS_SRC)/includes
CSS_OUT=$(BUILD)/css
CSS_TARGETS=$(patsubst $(CSS_SRC)/%.scss,$(CSS_OUT)/%.css,$(wildcard $(CSS_SRC)/*.scss))

.PHONY: all final css

final: CSS_FLAGS += -t compact --sourcemap=none
final: all

clean:
	rm -rf $(BUILD)/*

#
# CSS
#

css: $(CSS_TARGETS)

$(CSS_OUT):
	mkdir -p $(CSS_OUT)

$(CSS_TARGETS): $(CSS_OUT)/%.css : $(CSS_SRC)/%.scss | $(CSS_OUT)
	$(CSS_C) $(CSS_FLAGS) $< $@

a_main-packr.go: css
	packr

fileserver: a_main-packr.go main.go
	go build -o fileserver a_main-packr.go main.go

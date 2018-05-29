" Deckard syntax highlighting & folding
"
" Usage: Put following lines into ~/.vim/ftdetect/deckard.vim
" au BufRead,BufNewFile *.rpl set filetype=deckard
" au BufRead,BufNewFile *.stc set foldmethod=syntax

syntax keyword Keyword MATCH STEP ADJUST
syntax keyword Structure CONFIG_END
syntax keyword Function CHECK_ANSWER QUERY TIME_PASSES

syntax region deckardEntry matchgroup=Structure start="ENTRY_BEGIN" end="ENTRY_END" fold transparent
syntax region deckardRange matchgroup=Structure start="RANGE_BEGIN" end="RANGE_END" fold transparent
syntax region deckardScenario matchgroup=Structure start="SCENARIO_BEGIN" end="SCENARIO_END" fold transparent

syntax match deckardSection 'SECTION \+[^ ]\+'
syntax match deckardReply 'REPLY.*'

syntax match Comment ';.*$'

hi def link deckardEntry Folded
hi def link deckardRange Folded
hi def link deckardScenario Folded
hi def link deckardSection Special
hi def link deckardReply String

let b:current_syntax = 'deckard'

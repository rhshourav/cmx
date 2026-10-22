# CMX prototype
Byte-exact, integer-only context-mixing compressor with a JSON-safe string form.

    python3 gen_tests.py && python3 run_tests.py       # Python round-trip (verified)
    npm i pako                                          # JS needs pako (Node's built-in zlib does not match)
    python3 -c "import cmx;open('o.json','w').write(cmx.compress_to_json(open('img.png','rb').read()))"
    node cmx.mjs dec o.json out.png                     # decode in JS -> byte-identical file

Output JSON: {"cmx":1,"d":"<base85 string, JSON-safe alphabet>"}

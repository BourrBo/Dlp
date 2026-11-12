from dlp_cli.gitutil import COMMIT_MARK, parse_diff
from dlp_cli.ignore import IgnoreMatcher


def test_ignore_semantics():
    m = IgnoreMatcher(["# c", "*.log", "build/", "/root_only.txt", "docs/**/secret.md", "!keep.log", "tests/fixtures/*.txt"])
    assert m.matches("a/b/c.log") and m.matches("x.log")
    assert not m.matches("keep.log")
    assert m.matches("build/out.js") and m.matches("pkg/build/out.js")
    assert m.matches("root_only.txt") and not m.matches("sub/root_only.txt")
    assert m.matches("docs/a/b/secret.md") and m.matches("docs/secret.md")
    assert m.matches("tests/fixtures/a.txt") and not m.matches("tests/fixtures/sub/a.txt")
    assert not m.matches(".github/workflows/ci.yml")


DIFF = """diff --git a/a.py b/a.py
index 111..222 100644
--- a/a.py
+++ b/a.py
@@ -1,0 +2,2 @@
+one
++two starts with plus
@@ -10 +12 @@
-old
+new
diff --git a/my file.txt b/my file.txt
new file mode 100644
--- /dev/null
+++ b/my file.txt\t
@@ -0,0 +1,2 @@
+x
+y
\\ No newline at end of file
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-secret
-secret2
diff --git a/sub b/sub
--- a/sub
+++ b/sub
@@ -1 +1 @@
-Subproject commit aaa
+Subproject commit bbb
"""


def test_parse_diff_line_numbers_paths_and_deletions():
    got = [(l.path, l.line, l.text) for l in parse_diff(DIFF)]
    assert got == [
        ("a.py", 2, "one"), ("a.py", 3, "+two starts with plus"), ("a.py", 12, "new"),
        ("my file.txt", 1, "x"), ("my file.txt", 2, "y"),
    ]


def test_parse_diff_quoted_unicode_path_and_commit_marks():
    text = (f'{COMMIT_MARK}abc123\n\ndiff --git "a/caf\\303\\251.txt" "b/caf\\303\\251.txt"\n'
            '--- "a/caf\\303\\251.txt"\n+++ "b/caf\\303\\251.txt"\n@@ -0,0 +1 @@\n+hi\n'
            f'{COMMIT_MARK}def456\n\ndiff --git a/b b/b\n--- a/b\n+++ b/b\n@@ -0,0 +1 @@\n+yo\n')
    got = [(l.path, l.commit) for l in parse_diff(text)]
    assert got == [("café.txt", "abc123"), ("b", "def456")]

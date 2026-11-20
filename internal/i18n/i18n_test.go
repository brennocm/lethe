package i18n

import (
	"sort"
	"testing"
)

// The spec §16.6 test: every key of every language exists in every other one, and nothing is
// empty.
func TestI18N_KeysMatchAcrossLanguages(t *testing.T) {
	all, err := Tables()
	if err != nil {
		t.Fatal(err)
	}
	ref := all[Default]
	for _, l := range Langs {
		for _, other := range Langs {
			for sec, keys := range all[l] {
				for k, v := range keys {
					if v == "" {
						t.Errorf("%s: %s.%s is empty", l, sec, k)
					}
					if _, ok := all[other][sec][k]; !ok {
						t.Errorf("%s.%s exists in %s but not in %s", sec, k, l, other)
					}
				}
			}
		}
	}
	if len(ref) < 40 {
		t.Fatalf("only %d sections", len(ref))
	}
}

func TestI18N_EveryCheckHasTheThreeTexts(t *testing.T) {
	all, _ := Tables()
	var ids []string
	for sec := range all[Default] {
		if sec != "ui" && sec != "actions" {
			ids = append(ids, sec)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, k := range []string{"title", "meaning", "todo"} {
			if _, ok := all[Default][id][k]; !ok {
				t.Errorf("%s has no %s", id, k)
			}
		}
	}
}

func TestI18N_Parse(t *testing.T) {
	tb, err := Parse("# c\n[a]\nx = \"um \\\"dois\\\" \\\\ três\" # fim\n")
	if err != nil || tb["a"]["x"] != `um "dois" \ três` {
		t.Fatalf("%v %q", err, tb["a"]["x"])
	}
	for _, bad := range []string{"x = \"1\"", "[a]\nx = 1", "[a]\nx = \"1", "[a]\nx = \"1\" y", "[a]\n[a]", "[a]\nx = \"1\"\nx = \"2\"", "[a\n", "[a]\nx = \"\\q\""} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if Text("fr", "NET-001", "title") != Text("en-US", "NET-001", "title") || Norm("pt_BR") != "pt-BR" || Norm("") != "en-US" || UI("en", "state") != "State" || CheckText("en-US", "X-999").Title != "X-999" {
		t.Fatal("fallbacks")
	}
}

func FuzzI18N_Parse(f *testing.F) {
	f.Add("[a]\nx = \"y\"\n")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = Parse(s) })
}

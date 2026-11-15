package contracts

import "testing"

func TestAllSchemasCompile(t *testing.T) {
	if len(Names()) == 0 {
		t.Fatal("no schemas embedded")
	}
	// Any validation call triggers compilation of every schema.
	if err := ValidateJSON(Names()[0], []byte(`{}`)); err != nil && compileErr != nil {
		t.Fatalf("compile: %v", compileErr)
	}
}

func TestValidate_Version(t *testing.T) {
	good := `{"version":"dev","commit":"unknown","modified":false,"go_version":"go1.27.4",
	"platform":"linux/amd64","binary_sha256":"` + "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" + `","geo_db_date":"none"}`
	if err := ValidateJSON("version", []byte(good)); err != nil {
		t.Fatalf("good doc rejected: %v", err)
	}
	if err := ValidateJSON("version", []byte(`{"version":"dev","extra":1}`)); err == nil {
		t.Fatal("bad doc accepted")
	}
	if err := ValidateJSON("nope", []byte(`{}`)); err == nil {
		t.Fatal("unknown schema accepted")
	}
}

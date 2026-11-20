package main

import (
	"os"
	"path/filepath"
	"testing"
)

// One small sample project per tree-sitter language (testdata/<lang>):
// classes, functions, imports and calls resolved through imports, typed
// fields and parameters, "this"/"self" and static calls.

func TestJava(t *testing.T) {
	gi := index(discoverFixture(t, "testdata/java", false))
	ctl := "fn:java:src/main/java/com/example/web/UserController.java#UserController."
	svc := "fn:java:src/main/java/com/example/svc/UserService.java#UserService."
	gi.wantNodes(t, "class", "class:java:src/main/java/com/example/svc/UserService.java#UserService")
	gi.wantEdges(t,
		"file:src/main/java/com/example/web/UserController.java|imports|file:src/main/java/com/example/svc/UserService.java",
		ctl+"get|calls|"+svc+"find",         // field of declared type
		ctl+"get|calls|"+ctl+"format",       // same class
		ctl+"format|calls|"+svc+"normalise", // static call on an imported class
		svc+"find|calls|"+svc+"lookup",
		"class:java:src/main/java/com/example/svc/UserService.java#UserService|defines|"+svc+"find",
	)
}

func TestCSharp(t *testing.T) {
	gi := index(discoverFixture(t, "testdata/csharp", false))
	ctl := "fn:cs:Controllers/OrdersController.cs#OrdersController."
	gi.wantEdges(t,
		"file:Controllers/OrdersController.cs|imports|mod:Services",
		ctl+"Get|calls|fn:cs:Services/OrderService.cs#IOrderService.Describe", // interface method via typed field
		ctl+"Get|calls|fn:cs:Services/OrderService.cs#PriceCalculator.Total",  // var x = new T()
		"fn:cs:Services/OrderService.cs#PriceCalculator.Total|calls|fn:cs:Services/OrderService.cs#PriceCalculator.Round",
	)
}

func TestPHP(t *testing.T) {
	gi := index(discoverFixture(t, "testdata/php", false))
	ctl := "fn:php:app/Http/Controllers/InvoiceController.php#InvoiceController."
	billing := "fn:php:app/Services/Billing.php#Billing."
	gi.wantEdges(t,
		"file:app/Http/Controllers/InvoiceController.php|imports|file:app/Services/Billing.php",
		ctl+"show|calls|"+billing+"total",       // promoted constructor property
		ctl+"show|calls|"+ctl+"render",          // $this->
		ctl+"render|calls|"+billing+"format",    // Billing::format
		billing+"total|calls|"+billing+"format", // self::
	)
}

func TestRuby(t *testing.T) {
	gi := index(discoverFixture(t, "testdata/ruby", false))
	ctl := "fn:rb:app/controllers/accounts_controller.rb#AccountsController."
	svc := "fn:rb:lib/account_service.rb#AccountService."
	gi.wantEdges(t,
		"file:app/controllers/accounts_controller.rb|imports|file:lib/account_service.rb",
		ctl+"show|calls|"+svc+"lookup", // x = Klass.new; x.m
		ctl+"show|calls|"+ctl+"render_account",
		svc+"lookup|calls|"+svc+"normalise",
	)
}

func TestTypeScript(t *testing.T) {
	gi := index(discoverFixture(t, "testdata/ts", false))
	svc := "fn:ts:src/users.service.ts#"
	gi.wantEdges(t,
		"file:src/users.controller.ts|imports|file:src/users.service.ts",
		"fn:ts:src/users.controller.ts#UsersController.get|calls|"+svc+"UsersService.find", // constructor parameter property
		"fn:ts:src/users.controller.ts#UsersController.get|calls|"+svc+"slug",              // aliased named import
		svc+"UsersService.find|calls|"+svc+"UsersService.normalise",
		"file:src/components/UserCard.tsx|imports|file:src/users.service.ts", // TSX
		"fn:ts:src/components/UserCard.tsx#label|calls|"+svc+"slug",          // arrow function
		"fn:ts:src/components/UserCard.tsx#UserCard|calls|fn:ts:src/components/UserCard.tsx#label",
	)
}

func TestGoOnly(t *testing.T) {
	gi := index(discoverFixture(t, "testdata/fixture-repo", false))
	// Without the rule engine there are no routes, but parsing still works.
	for k, n := range gi.nodes {
		if n.Type == "route" {
			t.Errorf("route %s without the rule engine", k)
		}
	}
	gi.wantEdges(t, "fn:go:cmd/api.main|calls|fn:go:internal/httpapi.New")
}

func TestSensitiveStdImports(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/svc\n\ngo 1.22\n")
	write("cmd/server/main.go", "package main\n\nimport (\n\t\"net/http\"\n\t_ \"net/http/pprof\"\n\t\"os/exec\"\n)\n\nfunc main() {\n\t_ = exec.Command\n\t_ = http.ListenAndServe(\":8080\", nil)\n}\n")
	gi := index(discoverFixture(t, dir, false))
	n := gi.nodes["file:cmd/server/main.go"]
	if n == nil {
		t.Fatal("file node missing")
	}
	if got, _ := n.Attrs["sensitive_imports"].(string); got != "net/http/pprof:5 os/exec:6" {
		t.Errorf("sensitive_imports = %q", got)
	}
}

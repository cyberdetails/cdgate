package parse

import (
	"sort"
	"strings"
	"testing"
)

func dotnetNames(t *testing.T, file, body string) ([]string, int, error) {
	t.Helper()
	k, ok := Lookup(file)
	if !ok {
		t.Fatalf("%s not recognised", file)
	}
	local := 0
	ps, err := k.Parse(strings.NewReader(body), Options{LocalProjects: &local})
	var out []string
	for _, p := range ps {
		out = append(out, p.Name+"@"+p.Version)
	}
	sort.Strings(out)
	return out, local, err
}

// Rules from trivy 00b7394 pkg/dependency/parser/dotnet/core_deps.
func TestDepsJSON(t *testing.T) {
	body := `{
  "runtimeTarget": {"name": ".NETCoreApp,Version=v8.0/linux-x64"},
  "targets": {
    ".NETCoreApp,Version=v8.0/linux-x64": {
      "app/1.0.0": {"dependencies": {"Newtonsoft.Json": "13.0.1"}, "runtime": {"app.dll": {}}},
      "Newtonsoft.Json/13.0.1": {"runtime": {"lib/net6.0/Newtonsoft.Json.dll": {}}},
      "Analyzer.Only/1.0.0": {},
      "Null.Runtime/1.0.0": {"runtime": null},
      "Native.Only/2.0.0": {"native": {"x.so": {}}},
      "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/8.0.10": {"runtime": {"System.Private.CoreLib.dll": {}}},
      "runtimepack.Empty.Pack/1.0.0": {}
    }
  },
  "libraries": {
    "app/1.0.0": {"type": "project"},
    "Newtonsoft.Json/13.0.1": {"type": "package"},
    "Analyzer.Only/1.0.0": {"type": "package"},
    "Null.Runtime/1.0.0": {"type": "Package"},
    "Native.Only/2.0.0": {"type": "package"},
    "Not.In.Target/3.0.0": {"type": "package"},
    "Reference.Only/4.0.0": {"type": "reference"},
    "NoVersion": {"type": "package"},
    "runtimepack.Microsoft.NETCore.App.Runtime.linux-x64/8.0.10": {"type": "runtimepack"},
    "runtimepack.Empty.Pack/1.0.0": {"type": "runtimepack"}
  }
}`
	got, local, err := dotnetNames(t, "x/app.deps.json", body)
	want := "Microsoft.NETCore.App.Runtime.linux-x64@8.0.10,Native.Only@2.0.0,Newtonsoft.Json@13.0.1,Not.In.Target@3.0.0"
	if err != nil || strings.Join(got, ",") != want || local != 1 {
		t.Errorf("%v %d %v", got, local, err)
	}
	// without the runtime target every library counts
	got, _, _ = dotnetNames(t, "app.deps.json", strings.Replace(body, `"name": ".NETCoreApp,Version=v8.0/linux-x64"`, `"name": "other"`, 1))
	if len(got) != 7 { // all but the project, the reference and the unversioned entry
		t.Errorf("no target: %v", got)
	}
	if _, _, err := dotnetNames(t, "a.deps.json", "{"); err == nil {
		t.Error("broken JSON accepted")
	}
	if _, ok := Lookup("deps.json"); ok {
		t.Error("bare deps.json is not a .deps.json file")
	}
}

// Rules from trivy 00b7394 pkg/dependency/parser/nuget/packagesprops.
func TestPackagesProps(t *testing.T) {
	body := `<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup><X>1</X></PropertyGroup>
  <ItemGroup>
    <PackageVersion Include=" Serilog " Version=" 3.1.1 " />
    <PackageVersion Include="Polly" Version="$(PollyVersion)" />
    <PackageVersion Include="$(Name)" Version="1.0" />
    <PackageVersion Include="NoVersion" />
    <PackageVersion Include="OnlyVersion" Version="9.0.0" />
    <PackageVersion Include="Unclosed" Version="$(Half" />
    <PackageReference Update="Moq" Version="4.20.0" />
    <PackageReference Include="Dapper" Update="Ignored" Version="2.1.0" />
    <PackageReference Include="Serilog" Version="3.1.1" />
    <PackageReference Include="ChildVersion"><Version>1.0.0</Version></PackageReference>
  </ItemGroup>
  <ItemGroup><GlobalPackageReference Include="Global" Version="1.0.0" /></ItemGroup>
</Project>`
	for _, f := range []string{"Directory.Packages.props", "src/Packages.props", "x.PACKAGES.PROPS"} {
		got, _, err := dotnetNames(t, f, body)
		if err != nil || strings.Join(got, ",") != "Dapper@2.1.0,Moq@4.20.0,OnlyVersion@9.0.0,Serilog@3.1.1,Unclosed@$(Half" {
			t.Errorf("%s: %v %v", f, got, err)
		}
	}
	for name, b := range map[string]string{
		"wrong root": `<Foo><ItemGroup><PackageVersion Include="a" Version="1"/></ItemGroup></Foo>`,
		"doctype":    `<!DOCTYPE Project [<!ENTITY x "y">]><Project/>`,
		"empty":      ``,
	} {
		if _, _, err := dotnetNames(t, "Directory.Packages.props", b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, ok := Lookup("Directory.Build.props"); ok {
		t.Error("Directory.Build.props is not a packages.props file")
	}
}

func TestCargoWorkspaceCounted(t *testing.T) {
	got, local, err := dotnetNames(t, "Cargo.lock", "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n"+
		"[[package]]\nname = \"regex\"\nversion = \"1.10.2\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n")
	if err != nil || strings.Join(got, ",") != "regex@1.10.2" || local != 1 {
		t.Errorf("%v %d %v", got, local, err)
	}
}

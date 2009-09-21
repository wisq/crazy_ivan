# Generated by jeweler
# DO NOT EDIT THIS FILE
# Instead, edit Jeweler::Tasks in Rakefile, and run `rake gemspec`
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{crazy_ivan}
  s.version = "0.2.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Edward Ocampo-Gooding"]
  s.date = %q{2009-09-21}
  s.default_executable = %q{crazy_ivan}
  s.description = %q{Continuous integration should really just be a script that captures the output of running your project update & test commands and presents recent results in a static html page.

    By keeping test reports in json, per-project CI configuration in 3 probably-one-line scripts, things are kept simple, quick, and super extensible.

    Want to use git, svn, or hg? No problem.
    Need to fire off results to Twitter or Campfire? It's one line away.

    CI depends on cron.}
  s.email = %q{edward@edwardog.net}
  s.executables = ["crazy_ivan"]
  s.extra_rdoc_files = [
    "LICENSE",
     "README.rdoc"
  ]
  s.files = [
    ".gitignore",
     "LICENSE",
     "README.rdoc",
     "Rakefile",
     "TODO",
     "VERSION",
     "bin/crazy_ivan",
     "crazy_ivan.gemspec",
     "lib/crazy_ivan.rb",
     "lib/html_asset_crush.rb",
     "lib/report_assembler.rb",
     "lib/test_runner.rb",
     "templates/css/ci.css",
     "templates/index.html",
     "templates/javascript/json-template.js",
     "templates/javascript/prototype.js",
     "test/crazy_ivan_test.rb",
     "test/test_helper.rb",
     "vendor/json-1.1.7/CHANGES",
     "vendor/json-1.1.7/GPL",
     "vendor/json-1.1.7/README",
     "vendor/json-1.1.7/RUBY",
     "vendor/json-1.1.7/Rakefile",
     "vendor/json-1.1.7/TODO",
     "vendor/json-1.1.7/VERSION",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkComparison.log",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkExt#generator_fast-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkExt#generator_fast.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkExt#generator_pretty-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkExt#generator_pretty.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkExt#generator_safe-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkExt#generator_safe.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkExt.log",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkPure#generator_fast-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkPure#generator_fast.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkPure#generator_pretty-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkPure#generator_pretty.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkPure#generator_safe-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkPure#generator_safe.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkPure.log",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkRails#generator-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkRails#generator.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/GeneratorBenchmarkRails.log",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkComparison.log",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkExt#parser-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkExt#parser.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkExt.log",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkPure#parser-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkPure#parser.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkPure.log",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkRails#parser-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkRails#parser.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkRails.log",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkYAML#parser-autocorrelation.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkYAML#parser.dat",
     "vendor/json-1.1.7/benchmarks/data-p4-3GHz-ruby18/ParserBenchmarkYAML.log",
     "vendor/json-1.1.7/benchmarks/generator_benchmark.rb",
     "vendor/json-1.1.7/benchmarks/parser_benchmark.rb",
     "vendor/json-1.1.7/bin/edit_json.rb",
     "vendor/json-1.1.7/bin/prettify_json.rb",
     "vendor/json-1.1.7/data/example.json",
     "vendor/json-1.1.7/data/index.html",
     "vendor/json-1.1.7/data/prototype.js",
     "vendor/json-1.1.7/doc-templates/main.txt",
     "vendor/json-1.1.7/ext/json/ext/generator/extconf.rb",
     "vendor/json-1.1.7/ext/json/ext/generator/generator.c",
     "vendor/json-1.1.7/ext/json/ext/generator/unicode.c",
     "vendor/json-1.1.7/ext/json/ext/generator/unicode.h",
     "vendor/json-1.1.7/ext/json/ext/parser/extconf.rb",
     "vendor/json-1.1.7/ext/json/ext/parser/parser.c",
     "vendor/json-1.1.7/ext/json/ext/parser/parser.rl",
     "vendor/json-1.1.7/ext/json/ext/parser/unicode.c",
     "vendor/json-1.1.7/ext/json/ext/parser/unicode.h",
     "vendor/json-1.1.7/install.rb",
     "vendor/json-1.1.7/lib/json.rb",
     "vendor/json-1.1.7/lib/json/Array.xpm",
     "vendor/json-1.1.7/lib/json/FalseClass.xpm",
     "vendor/json-1.1.7/lib/json/Hash.xpm",
     "vendor/json-1.1.7/lib/json/Key.xpm",
     "vendor/json-1.1.7/lib/json/NilClass.xpm",
     "vendor/json-1.1.7/lib/json/Numeric.xpm",
     "vendor/json-1.1.7/lib/json/String.xpm",
     "vendor/json-1.1.7/lib/json/TrueClass.xpm",
     "vendor/json-1.1.7/lib/json/add/core.rb",
     "vendor/json-1.1.7/lib/json/add/rails.rb",
     "vendor/json-1.1.7/lib/json/common.rb",
     "vendor/json-1.1.7/lib/json/editor.rb",
     "vendor/json-1.1.7/lib/json/ext.rb",
     "vendor/json-1.1.7/lib/json/json.xpm",
     "vendor/json-1.1.7/lib/json/pure.rb",
     "vendor/json-1.1.7/lib/json/pure/generator.rb",
     "vendor/json-1.1.7/lib/json/pure/parser.rb",
     "vendor/json-1.1.7/lib/json/version.rb",
     "vendor/json-1.1.7/tests/fixtures/fail1.json",
     "vendor/json-1.1.7/tests/fixtures/fail10.json",
     "vendor/json-1.1.7/tests/fixtures/fail11.json",
     "vendor/json-1.1.7/tests/fixtures/fail12.json",
     "vendor/json-1.1.7/tests/fixtures/fail13.json",
     "vendor/json-1.1.7/tests/fixtures/fail14.json",
     "vendor/json-1.1.7/tests/fixtures/fail18.json",
     "vendor/json-1.1.7/tests/fixtures/fail19.json",
     "vendor/json-1.1.7/tests/fixtures/fail2.json",
     "vendor/json-1.1.7/tests/fixtures/fail20.json",
     "vendor/json-1.1.7/tests/fixtures/fail21.json",
     "vendor/json-1.1.7/tests/fixtures/fail22.json",
     "vendor/json-1.1.7/tests/fixtures/fail23.json",
     "vendor/json-1.1.7/tests/fixtures/fail24.json",
     "vendor/json-1.1.7/tests/fixtures/fail25.json",
     "vendor/json-1.1.7/tests/fixtures/fail27.json",
     "vendor/json-1.1.7/tests/fixtures/fail28.json",
     "vendor/json-1.1.7/tests/fixtures/fail3.json",
     "vendor/json-1.1.7/tests/fixtures/fail4.json",
     "vendor/json-1.1.7/tests/fixtures/fail5.json",
     "vendor/json-1.1.7/tests/fixtures/fail6.json",
     "vendor/json-1.1.7/tests/fixtures/fail7.json",
     "vendor/json-1.1.7/tests/fixtures/fail8.json",
     "vendor/json-1.1.7/tests/fixtures/fail9.json",
     "vendor/json-1.1.7/tests/fixtures/pass1.json",
     "vendor/json-1.1.7/tests/fixtures/pass15.json",
     "vendor/json-1.1.7/tests/fixtures/pass16.json",
     "vendor/json-1.1.7/tests/fixtures/pass17.json",
     "vendor/json-1.1.7/tests/fixtures/pass2.json",
     "vendor/json-1.1.7/tests/fixtures/pass26.json",
     "vendor/json-1.1.7/tests/fixtures/pass3.json",
     "vendor/json-1.1.7/tests/test_json.rb",
     "vendor/json-1.1.7/tests/test_json_addition.rb",
     "vendor/json-1.1.7/tests/test_json_fixtures.rb",
     "vendor/json-1.1.7/tests/test_json_generate.rb",
     "vendor/json-1.1.7/tests/test_json_rails.rb",
     "vendor/json-1.1.7/tests/test_json_unicode.rb",
     "vendor/json-1.1.7/tools/fuzz.rb",
     "vendor/json-1.1.7/tools/server.rb"
  ]
  s.homepage = %q{http://github.com/edward/crazy_ivan}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{crazyivan}
  s.rubygems_version = %q{1.3.5}
  s.summary = %q{Crazy Ivan (CI) is simplest possible continuous integration tool.}
  s.test_files = [
    "test/crazy_ivan_test.rb",
     "test/test_helper.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end

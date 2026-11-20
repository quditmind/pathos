Test data for the end-to-end tests (labelled example data, not real code):

- `threat-model-repo/`: a copy of the CodeGraph discovery fixture repository
  (`workers/graph/discover/testdata/fixture-repo`), uploaded by
  `threatmodels.spec.ts` as a Local PC repository so the real worker-graph
  builds its CodeGraph and the threat model is generated from it.
- `rea-svc/`: a small Go service (test data) with a blank import of
  `net/http/pprof`. `reverse-engineering.spec.ts` uploads it as a Local PC
  repository (CodeGraph is built from it by the real worker-graph), builds
  it with the pinned Go image, attests its SLSA provenance with cosign and
  a throw-away key, uploads the binary as a build artifact and analyses it
  with the real worker-rea.

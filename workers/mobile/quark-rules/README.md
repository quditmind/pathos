# PATHOS Quark-Engine rules

Behaviour rules for [Quark-Engine](https://github.com/quark-engine/quark-engine)
written for PATHOS (Apache-2.0, like the rest of PATHOS). Each rule names two
Android API calls; Quark reports a crime with a confidence of 20 % to 100 %
depending on how many of its five stages match (permissions, both APIs present,
both called in one method, in order, with data passed from the first to the
second).

The community rule set (quark-engine/quark-rules) has no licence, so it is not
bundled with the worker-mobile image. An operator who has the right to use it
can mount it at `/opt/pathos/mobile/quark-rules-extra` (read-only); the
`quark-engine` tool then runs both sets.

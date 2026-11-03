import EsecCore
import Testing
@Test func familiarEnvironmentOrdering() {
 #expect(SecretEnvironmentOrder.sorted(["test","production","dev","staging","alpha"]) == ["dev","staging","production","alpha","test"])
}

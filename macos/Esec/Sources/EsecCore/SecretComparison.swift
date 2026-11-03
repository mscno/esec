import Foundation

/// Familiar deployment stages first; component environments such as api.prod
/// use their last segment. Unknown names follow production alphabetically.
public enum SecretEnvironmentOrder {
    public static func sorted(_ environments: [String]) -> [String] {
        environments.sorted {
            let a = rank($0), b = rank($1)
            if a != b { return a < b }
            let lhs = $0.isEmpty ? "default" : $0.lowercased()
            let rhs = $1.isEmpty ? "default" : $1.lowercased()
            return lhs == rhs ? $0 < $1 : lhs < rhs
        }
    }

    private static func rank(_ environment: String) -> Int {
        switch environment.lowercased().split(separator: ".").last {
        case "dev", "development": 0
        case "stage", "staging": 1
        case "prod", "production": 2
        default: 3
        }
    }
}

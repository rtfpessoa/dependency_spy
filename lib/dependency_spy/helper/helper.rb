module DependencySpy
  class Helper
    def self.is_severity_above_threshold?(severity='unknown', severity_threshold)
      return true if severity_threshold == 'low' || severity == 'unknown'
      return %w(medium high).include? severity if severity_threshold == 'medium'
      return severity == 'high' if severity_threshold == 'high'
      false
    end
  end
end
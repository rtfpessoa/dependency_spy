require 'yaml'

module DependencySpy
  class ConfigFile
    SAFE_CONFIG_PARAMS = [
      'path',
      'files',
      'formatter',
      'platform',
      'output-path',
      'database-path',
      'offline',
      'severity-threshold',
      'with-color',
      'ignore',
      'vuln-db-path'].freeze

    def self.get_config(config_file_path=nil)
      if !config_file_path.nil? && !File.file?(config_file_path)
        puts 'Config file specified but not found.'
        exit(10)

      end

      begin
        file_path = config_file_path || ".depspy.yml"
        config = YAML.load_file(file_path) || {}
        config.slice(*SAFE_CONFIG_PARAMS)

      rescue Errno::ENOENT
        {}

      rescue Psych::SyntaxError => e
        puts 'Config File Parsing Error:'
        puts e.message
        exit(10)

      end
    end
  end
end

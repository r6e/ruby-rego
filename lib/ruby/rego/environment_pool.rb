# frozen_string_literal: true

require_relative "environment"

module Ruby
  module Rego
    # Pools Environment instances for reuse across evaluations.
    # Thread-safe for concurrent checkouts/checkins.
    class EnvironmentPool
      # @param max_size [Integer, nil] maximum pool size for reuse (nil means unbounded)
      # :reek:ControlParameter
      def initialize(max_size: nil)
        pool = [] # @type var pool: Array[Environment]
        @pool = pool
        @max_size = normalized_max_size(max_size)
        @mutex = Mutex.new
      end

      # @param state [Environment::State]
      # @return [Environment]
      def checkout(state)
        @mutex.synchronize do
          environment = @pool.pop # @type var environment: Environment?
          return Environment.from_state(state) unless environment

          environment.reset!(state)
        end
      end

      # @param environment [Environment]
      # @return [void]
      def checkin(environment)
        @mutex.synchronize do
          return nil if max_size_full?(@pool.length)

          environment.prepare_for_pool
          @pool << environment
        end
        nil
      end

      private

      attr_reader :max_size

      def max_size_full?(current_size)
        return false if max_size.equal?(unbounded)

        current_size >= max_size
      end

      def unbounded
        @unbounded ||= Object.new.freeze
      end

      # :reek:NilCheck
      def normalized_max_size(value)
        case value
        when nil
          unbounded
        when Integer
          raise ArgumentError, "max_size must be non-negative" if value.negative?

          value
        else
          raise ArgumentError, "max_size must be an Integer"
        end
      end
    end
  end
end

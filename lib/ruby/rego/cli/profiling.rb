# frozen_string_literal: true

# Evaluation profiling (timing and memory) for rego-validate.
module RegoValidate
  # Captures timing and memory statistics for policy evaluation.
  class Profiler
    # Holds a single profiler sample.
    Sample = Struct.new(:label, :duration_ms, :allocations, :memory_bytes, :top_objects)

    # Rendering helpers for profiler samples.
    class Sample
      def report_line
        parts = [
          "  #{label}: #{format_duration}",
          "allocs +#{allocations}",
          "mem #{format_bytes}"
        ]
        parts.join(", ")
      end

      def top_objects_line
        return nil if top_objects.empty?

        "  top allocations: #{top_objects.join(", ")}"
      end

      private

      def format_duration
        format("%.2f ms", duration_ms)
      end

      def format_bytes
        ByteFormatter.new(memory_bytes).render
      end
    end

    # Formats byte sizes for profiler output.
    class ByteFormatter
      def initialize(bytes)
        @sign = bytes.negative? ? "-" : "+"
        @size = bytes.abs
      end

      def render
        unit, value = if size < 1024
                        ["B", size.to_s]
                      elsif size < 1024 * 1024
                        ["KB", Kernel.format("%.2f", size / 1024.0)]
                      else
                        ["MB", Kernel.format("%.2f", size / (1024.0 * 1024.0))]
                      end
        "#{sign}#{value} #{unit}"
      end

      private

      attr_reader :sign, :size
    end

    # Captures a memory snapshot for diffing.
    class Snapshot
      class << self
        def capture
          require "objspace"
          build_snapshot(memsize: ObjectSpace.memsize_of_all, objects: ObjectSpace.count_objects)
        rescue LoadError, NoMethodError
          build_snapshot(memsize: 0, objects: empty_object_counts)
        end

        def capture_before
          capture
        end

        def capture_after
          capture
        end

        private

        def build_snapshot(memsize:, objects:)
          new(
            allocated: GC.stat[:total_allocated_objects],
            memsize: memsize,
            objects: objects
          )
        end

        def empty_object_counts
          {} # @type var objects: Hash[Symbol, Integer]
        end
      end

      def initialize(allocated:, memsize:, objects:)
        @allocated = allocated
        @memsize = memsize
        @objects = objects
      end

      attr_reader :allocated, :memsize, :objects

      def delta(other)
        Delta.new(
          allocations: other.allocated - allocated,
          memory_bytes: other.memsize - memsize,
          object_deltas: object_delta_map(other.objects)
        )
      end

      private

      def object_delta_map(after_objects)
        deltas = {} # @type var deltas: Hash[Symbol, Integer]
        after_objects.each { |key, count| add_delta(deltas, key, count) }
        deltas
      end

      def add_delta(deltas, key, count)
        return if Delta.skip_key?(key)

        delta = count - (objects[key] || 0)
        deltas[key] = delta if delta.positive?
      end
    end

    # Computes deltas between snapshots.
    class Delta
      SKIP_KEYS = %i[TOTAL FREE].freeze

      def self.skip_key?(key)
        SKIP_KEYS.include?(key)
      end

      def initialize(allocations:, memory_bytes:, object_deltas:)
        @allocations = allocations
        @memory_bytes = memory_bytes
        @object_deltas = object_deltas
      end

      attr_reader :allocations, :memory_bytes, :object_deltas

      def top_objects(limit: 3)
        object_deltas
          .sort_by { |(_, count)| -count }
          .first(limit)
          .map { |(key, count)| "#{key} +#{count}" }
      end
    end

    # Tracks measurement state for a single sample.
    class Measurement
      def initialize(label:, before:, start:)
        @label = label
        @before = before
        @start = start
      end

      def finish(after:, finish:)
        delta = before.delta(after)
        Sample.new(
          label: label,
          duration_ms: ((finish - start) * 1000.0),
          allocations: delta.allocations,
          memory_bytes: delta.memory_bytes,
          top_objects: delta.top_objects
        )
      end

      private

      attr_reader :before, :label, :start
    end

    # @param stderr [IO]
    def initialize(stderr: $stderr)
      @stderr = stderr
      @samples = [] # @type var @samples: Array[Sample]
      @clock = Process.method(:clock_gettime)
    end

    # @param label [String]
    # @return [Object]
    def measure(label)
      measurement = start_measurement(label)
      result = yield
      result
    ensure
      finish_measurement(measurement)
    end

    # @return [void]
    def report
      return if samples.empty?

      stderr.puts("Profile:")
      report_samples
      report_hotspot
    end

    private

    attr_reader :clock, :samples, :stderr

    def report_samples
      samples.each do |sample|
        stderr.puts(sample.report_line)
        top_line = sample.top_objects_line
        stderr.puts(top_line) if top_line
      end
    end

    def report_hotspot
      hotspot = samples.max_by(&:duration_ms)
      stderr.puts("  hotspot: #{hotspot.label}") if hotspot
    end

    def start_measurement(label)
      Measurement.new(
        label: label,
        before: Snapshot.capture_before,
        start: clock_time
      )
    end

    def finish_measurement(measurement)
      return unless measurement

      sample = measurement.finish(after: Snapshot.capture_after, finish: clock_time)
      samples << sample
    end

    def clock_time
      clock.call(Process::CLOCK_MONOTONIC)
    end
  end
end

# frozen_string_literal: true

FactoryBot.define do
  factory :rego_string_value, class: "Ruby::Rego::StringValue" do
    value { "example" }

    initialize_with { new(value) }
  end

  factory :rego_number_value, class: "Ruby::Rego::NumberValue" do
    value { 42 }

    initialize_with { new(value) }
  end

  factory :rego_boolean_value, class: "Ruby::Rego::BooleanValue" do
    value { true }

    initialize_with { new(value) }
  end

  factory :rego_null_value, class: "Ruby::Rego::NullValue" do
    initialize_with { new }
  end

  factory :rego_undefined_value, class: "Ruby::Rego::UndefinedValue" do
    initialize_with { new }
  end
end

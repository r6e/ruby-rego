package features

even_numbers := [n | some n in input.numbers; n % 2 == 0]

number_set := {n | some n in input.numbers; n > 2}

keyed := {k: v | some k in input.keys; v := input.map[k]}

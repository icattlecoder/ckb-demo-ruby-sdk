# This contract needs 2 signed arguments:
# 1. token name, this is here so we can have different lock hash for
# different token for ease of querying. In the actual contract this is
# not used.
# 2. pubkey, used to identify token owner
# This contract also accepts two optional unsigned arguments:
# 3. signature, signature used to present ownership
# 4. hash indices, see below for explanation
# If they exist, we will do the proper signature verification way, if not
# we will check for lock hash, and only accept transactions that have more
# tokens in the output cell than input cell so as to allow receiving tokens.
if ARGV.length < 2
  raise "Not enough arguments!"
end

def hex_to_bin(s)
  if s.start_with?("0x")
    s = s[2..-1]
  end
  s.each_char.each_slice(2).map(&:join).map(&:hex).map(&:chr).join
end

tx = CKB.load_tx

if ARGV.length >= 4
  sha3 = Sha3.new

  ARGV.drop(3).each do |argument|
    sha3.update(argument)
  end

  # hash_indices is passed in as a string of format "1,2|3,4|5", this means
  # hash index 1 and 2 of inputs, index 3 and 4 of outputs, and index 5 of
  # deps. All indices here are 0-based.
  hash_indices = ARGV[3].split("|").map { |s| s.split(",") }
  (hash_indices[0] || []).each do |input_index|
    input_index = input_index.to_i
    input = tx["inputs"][input_index]
    sha3.update(input["hash"])
    sha3.update(input["index"].to_s)
    sha3.update(CKB.load_script_hash(input_index, CKB::INPUT, CKB::LOCK))
  end
  (hash_indices[1] || []).each do |output_index|
    output_index = output_index.to_i
    output = tx["outputs"][output_index]
    sha3.update(output["capacity"].to_s)
    sha3.update(output["lock"])
    # TODO: to ensure security we should also verify that contract args contain
    # type hash for the contract script. Otherwise we cannot be sure that this
    # contract won't be exploited. We will add this later when we figure out the
    # best way to keep args.
    if hash = CKB.load_script_hash(output_index, CKB::OUTPUT, CKB::CONTRACT)
      sha3.update(hash)
    end
  end
  (hash_indices[2] || []).each do |dep_index|
    dep_index = dep_index.to_i
    dep = tx["deps"][dep_index]
    sha3.update(dep["hash"])
    sha3.update(dep["index"].to_s)
  end
  hash = sha3.final

  pubkey = ARGV[1]
  signature = ARGV[2]

  unless Secp256k1.verify(hex_to_bin(pubkey), hex_to_bin(signature), hash)
    raise "Signature verification error!"
  end
else
  current_script_hash = CKB.load_current_script_hash
  input_matches = tx["inputs"].length.times.select do |i|
    CKB.load_script_hash(i, CKB::INPUT, CKB::LOCK) == current_script_hash
  end
  if input_matches.length > 1
    raise "Invalid input cell number!"
  end
  output_matches = tx["outputs"].length.times.select do |i|
    CKB.load_script_hash(i, CKB::OUTPUT, CKB::LOCK) == current_script_hash
  end
  if output_matches.length > 1
    raise "Invalid output cell number!"
  end
  input_index = input_matches[0]
  output_index = output_matches[0]
  if CKB.load_script_hash(input_index, CKB::INPUT, CKB::CONTRACT) !=
     CKB.load_script_hash(input_index, CKB::OUTPUT, CKB::CONTRACT)
    raise "You cannot modify contract script!"
  end
  # TODO: we should also check input and output cells' capacity matches, right
  # now there is no way for us to know input cell's capacity
  input_amount = CKB::Cell.new(CKB::INPUT, input_matches[0]).read(0, 8).unpack("Q<")[0]
  output_amount = CKB::Cell.new(CKB::OUTPUT, output_matches[0]).read(0, 8).unpack("Q<")[0]
  unless output_amount > input_amount
    raise "You can only deposit tokens here!"
  end
end

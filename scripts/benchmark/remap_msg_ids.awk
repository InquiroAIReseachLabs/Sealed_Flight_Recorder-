# Reads `od -An -v -tu1` of whole ULog records and writes them as bytes, with the msg_id of every
# subscription ('A') and data ('D') record raised by `add`; stops after the record that brings
# the bytes written to `limit` or more.
BEGIN { hdr = 0; out = 0 }
{
  for (i = 1; i <= NF; i++) {
    b = $i + 0
    if (hdr < 3) {
      h[hdr++] = b
      if (hdr == 3) {
        size = h[0] + 256 * h[1]; type = h[2]; k = 0
        printf "%c%c%c", h[0], h[1], h[2]; out += 3
        if (size == 0) { hdr = 0; if (out >= limit) exit }
      }
      continue
    }
    if ((type == 65 && k == 1) || (type == 68 && k == 0)) { lo = b; k++; continue }
    if ((type == 65 && k == 2) || (type == 68 && k == 1)) {
      id = lo + 256 * b + add
      printf "%c%c", id % 256, int(id / 256); out += 2
    } else {
      printf "%c", b; out++
    }
    k++
    if (k == size) { hdr = 0; if (out >= limit) exit }
  }
}

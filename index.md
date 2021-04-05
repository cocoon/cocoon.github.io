### jxl.Net

jpeg-xl dotnet csharp / c# encoder decoder wrapper and jpeg-xl 
encoder GUI (WPF) with live jpeg-xl image preview and comparison slider 

For more details see [jxl.Net](https://github.com/cocoon/jxl.Net) and visit the [Wiki](https://github.com/cocoon/jxl.Net/wiki)

[![jpeg-xl encoder wrapper c# / csharp](https://cocoon.github.io/encoder.png)](https://github.com/cocoon/jxl.Net/)

# Wiki
* [Where to get encoder and decoder binaries](https://github.com/cocoon/jxl.Net/wiki/Where-to-get-encoder-and-decoder-binaries)
* [Build Instructions jpeg xl](https://github.com/cocoon/jxl.Net/wiki/Build-Instructions-jpeg-xl)
* [JPEG-XL Header Magic Bytes](https://github.com/cocoon/jxl.Net/wiki/jpeg-xl-header-magic-bytes)

## Changelog
* [jpeg-xl Chanelog](https://gitlab.com/wg1/jpeg-xl/-/raw/master/debian/changelog)


### More
  
[Repositories](https://github.com/cocoon)



# JPEG-XL Header Magic Bytes

## Variants
  
There are 3 (or more) different types of jpeg-xl headers:
  
* JXL_SIG_CODESTREAM (FF 0A)
* JPEG XL container / JPEG lossless transcode (00 00 00 0C 4A 58 4C)
* Unknown box (00 00 00 18 75 6E 6B 6E)





### JXL_SIG_CODESTREAM (FF 0A)

Result of:   
`
cjxl.exe example.png example.jxl
`

Example:
```
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  FF 0A F2 18 68 40 80 95 08 08 10 00 25 20 00 00  ÿ.ò.h@€•....% ..
```

### JPEG XL container / JPEG lossless transcode (00 00 00 0C 4A 58 4C)

Result of:   
`
cjxl.exe example.jpg example.jxl
`

Example:
```
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  00 00 00 0C 4A 58 4C 20 0D 0A 87 0A 00 00 00 14  ....JXL ..‡.....
```

### Unknown box (00 00 00 18 75 6E 6B 6E)

Example:  
```
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  00 00 00 18 75 6E 6B 6E 00 00 00 00 00 00 00 00  ....unkn........
```

  
  
## Code snippets

[decode_test.cc TEST(DecodeTest, JxlSignatureCheckTest)](https://gitlab.com/wg1/jpeg-xl/-/blob/v0.3.7/lib/jxl/decode_test.cc#L618)
  
```
TEST(DecodeTest, JxlSignatureCheckTest) {
  std::vector<std::pair<int, std::vector<uint8_t>>> tests = {
      // No JPEGXL header starts with 'a'.
      {JXL_SIG_INVALID, {'a'}},
      {JXL_SIG_INVALID, {'a', 'b', 'c', 'd', 'e', 'f'}},

      // Empty file is not enough bytes.
      {JXL_SIG_NOT_ENOUGH_BYTES, {}},

      // JPEGXL headers.
      {JXL_SIG_NOT_ENOUGH_BYTES, {0xff}},  // Part of a signature.
      {JXL_SIG_INVALID, {0xff, 0xD8}},     // JPEG-1
      {JXL_SIG_CODESTREAM, {0xff, 0x0a}},

      // JPEGXL container file.
      {JXL_SIG_CONTAINER,
       {0, 0, 0, 0xc, 'J', 'X', 'L', ' ', 0xD, 0xA, 0x87, 0xA}},
      // Ending with invalid byte.
      {JXL_SIG_INVALID, {0, 0, 0, 0xc, 'J', 'X', 'L', ' ', 0xD, 0xA, 0x87, 0}},
      // Part of signature.
      {JXL_SIG_NOT_ENOUGH_BYTES,
       {0, 0, 0, 0xc, 'J', 'X', 'L', ' ', 0xD, 0xA, 0x87}},
      {JXL_SIG_NOT_ENOUGH_BYTES, {0}},
  };
  for (const auto& test : tests) {
    EXPECT_EQ(test.first,
              JxlSignatureCheck(test.second.data(), test.second.size()))
        << "Where test data is " << ::testing::PrintToString(test.second);
  }
}

```


[decode_test.cc](https://gitlab.com/wg1/jpeg-xl/-/blob/v0.3.7/lib/jxl/decode_test.cc#L215)

```
  if (add_container != kCSBF_None) {
    // Header with signature box and ftyp box.
    const uint8_t header[] = {0,    0,    0,    0xc,  0x4a, 0x58, 0x4c, 0x20,
                              0xd,  0xa,  0x87, 0xa,  0,    0,    0,    0x14,
                              0x66, 0x74, 0x79, 0x70, 0x6a, 0x78, 0x6c, 0x20,
                              0,    0,    0,    0,    0x6a, 0x78, 0x6c, 0x20};
    // Unknown box, could be a box added by user, decoder must be able to skip
    // over it. Type is set to 'unkn', size to 24, contents to 16 0's.
    const uint8_t unknown[] = {0, 0, 0, 0x18, 0x75, 0x6e, 0x6b, 0x6e,
                               0, 0, 0, 0,    0,    0,    0,    0,
                               0, 0, 0, 0,    0,    0,    0,    0};
    // same as the unknown box, but with size set to 0, this can only be a final
    // box
    const uint8_t unknown_end[] = {0, 0, 0, 0, 0x75, 0x6e, 0x6b, 0x6e,
                                   0, 0, 0, 0, 0,    0,    0,    0,
                                   0, 0, 0, 0, 0,    0,    0,    0};
```

[decode.cc ReadSignature](https://gitlab.com/wg1/jpeg-xl/-/blob/v0.3.7/lib/jxl/decode.cc#L109)  
  
```
JxlSignature ReadSignature(const uint8_t* buf, size_t len, size_t* pos) {
  if (*pos >= len) return JXL_SIG_NOT_ENOUGH_BYTES;

  buf += *pos;
  len -= *pos;

  // JPEG XL codestream: 0xff 0x0a
  if (len >= 1 && buf[0] == 0xff) {
    if (len < 2) {
      return JXL_SIG_NOT_ENOUGH_BYTES;
    } else if (buf[1] == jxl::kCodestreamMarker) {
      *pos += 2;
      return JXL_SIG_CODESTREAM;
    } else {
      return JXL_SIG_INVALID;
    }
  }

  // JPEG XL container
  if (len >= 1 && buf[0] == 0) {
    if (len < 12) {
      return JXL_SIG_NOT_ENOUGH_BYTES;
    } else if (buf[1] == 0 && buf[2] == 0 && buf[3] == 0xC && buf[4] == 'J' &&
               buf[5] == 'X' && buf[6] == 'L' && buf[7] == ' ' &&
               buf[8] == 0xD && buf[9] == 0xA && buf[10] == 0x87 &&
               buf[11] == 0xA) {
      *pos += 12;
      return JXL_SIG_CONTAINER;
    } else {
      return JXL_SIG_INVALID;
    }
  }

  return JXL_SIG_INVALID;
}
``` 

## Decoder process
  
[decode.cc JxlDecoderProcessInput](https://gitlab.com/wg1/jpeg-xl/-/blob/v0.3.7/lib/jxl/decode.cc#L1328)
  
``` 
JxlDecoderStatus JxlDecoderProcessInput(JxlDecoder* dec) {
  const uint8_t** next_in = &dec->next_in;
  size_t* avail_in = &dec->avail_in;
  if (dec->stage == DecoderStage::kInited) {
    dec->stage = DecoderStage::kStarted;
  }
  if (dec->stage == DecoderStage::kError) {
    return JXL_API_ERROR(
        "Cannot keep using decoder after it encountered an error, use "
        "JxlDecoderReset to reset it");
  }
  if (dec->stage == DecoderStage::kFinished) {
    return JXL_API_ERROR(
        "Cannot keep using decoder after it finished, use JxlDecoderReset to "
        "reset it");
  }

  if (!dec->got_signature) {
    JxlSignature sig = JxlSignatureCheck(*next_in, *avail_in);
    if (sig == JXL_SIG_INVALID) return JXL_API_ERROR("invalid signature");
    if (sig == JXL_SIG_NOT_ENOUGH_BYTES) return JXL_DEC_NEED_MORE_INPUT;

    dec->got_signature = true;

    if (sig == JXL_SIG_CONTAINER) {
      dec->have_container = 1;
    }
  }

  // Available codestream bytes, may differ from *avail_in if there is another
  // box behind the current position, in the dec->have_container case.
  size_t csize = *avail_in;

  if (dec->have_container) {
    /*
    Process bytes as follows:
    *) find the box(es) containing the codestream
    *) support codestream split over multiple partial boxes
    *) avoid copying bytes to the codestream vector if the decoding will be
     one-shot, when the user already provided everything contiguously in
     memory
    *) copy to codestream vector, and update next_in so user can delete the data
    on their side, once we know it's not oneshot. This relieves the user from
    continuing to store the data.
    *) also copy to codestream if one-shot but the codestream is split across
    multiple boxes: this copying can be avoided in the future if the C++
    decoder is updated for streaming, but for now it requires all consecutive
    data at once.
    */

    if (dec->first_codestream_seen && !dec->last_codestream_seen &&
        dec->codestream_end != 0 && dec->file_pos < dec->codestream_end &&
        dec->file_pos + *avail_in >= dec->codestream_end &&
        !dec->codestream.empty()) {
      // dec->file_pos in a codestream, not in surrounding box format bytes, but
      // the end of the current codestream part is in the current input, and
      // boxes that can contain a next part of the codestream could be present.
      // Therefore, store the known codestream part, and ensure processing of
      // boxes below will trigger. This is only done if
      // !dec->codestream.empty(), that is, we're already streaming.

      // Size of the codestream, excluding potential boxes that come after it.
      csize = *avail_in;
      if (dec->codestream_end && csize > dec->codestream_end - dec->file_pos) {
        csize = dec->codestream_end - dec->file_pos;
      }
      dec->codestream.insert(dec->codestream.end(), *next_in, *next_in + csize);
      dec->file_pos += csize;
      *next_in += csize;
      *avail_in -= csize;
    }

    if (dec->inside_jpeg_reconstruction_box) {
      // We are inside a JPEG reconstruction box.
      JxlDecoderStatus recon_result =
          JxlDecoderProcessJPEGReconstruction(dec, next_in, avail_in);
      if (recon_result == JXL_DEC_JPEG_RECONSTRUCTION) {
        // If successful JPEG reconstruction, return the success if the user
        // cares about it, otherwise continue.
        if (dec->events_wanted & recon_result) {
          dec->events_wanted &= ~recon_result;
          return recon_result;
        }
      } else {
        // If anything else, return the result.
        return recon_result;
      }
    }

    if (!dec->last_codestream_seen &&
        (dec->codestream_begin == 0 ||
         (dec->codestream_end != 0 && dec->file_pos >= dec->codestream_end))) {
      size_t pos = 0;
      // after this for loop, either we should be in a part of the data that is
      // codestream (not boxes), or have returned that we need more input.
      for (;;) {
        const uint8_t* in = *next_in;
        size_t size = *avail_in;
        if (size == 0) {
          // If the remaining size is 0, we are exactly after a full box. We
          // can't know for sure if this is the last box or not since more bytes
          // can follow, but do not return NEED_MORE_INPUT, instead break and
          // let the codestream-handling code determine if we need more.
          break;
        }
        if (OutOfBounds(pos, 8, size)) {
          dec->basic_info_size_hint =
              InitialBasicInfoSizeHint() + pos + 8 - dec->file_pos;
          return JXL_DEC_NEED_MORE_INPUT;
        }
        size_t box_start = pos;
        uint64_t box_size = LoadBE32(in + pos);
        char type[5] = {0};
        memcpy(type, in + pos + 4, 4);
        pos += 8;
        if (box_size == 1) {
          if (OutOfBounds(pos, 8, size)) return JXL_DEC_NEED_MORE_INPUT;
          box_size = LoadBE64(in + pos);
          pos += 8;
        }
        size_t header_size = pos - box_start;
        if (box_size > 0 && box_size < header_size) {
          return JXL_API_ERROR("invalid box size");
        }
        size_t avail_contents_size =
            (box_size == 0)
                ? (size - pos)
                : std::min<size_t>(size - pos, box_size - pos + box_start);
        size_t contents_size =
            (box_size == 0) ? 0 : (box_size - pos + box_start);
        // TODO(lode): support the case where the header is split across
        // multiple codestream boxes
        if (strcmp(type, "jxlc") == 0 || strcmp(type, "jxlp") == 0) {
          // A JXL container file either has exactly one "jxlc" box with the
          // full codestream, or has one or more "jxlp" boxes with parts of the
          // codestream, but never both. So we only know for sure that it's the
          // last codestream box if either it was the only one (jxlc), or it
          // was one with unlimited size (box_size == 0), which can only happen
          // to the last box in the entire container file. However, it is
          // possible that the last jxlp box is not the last box of the
          // container or does not use box_size == 0, in that case it can happen
          // that last_codestream is false even though it is the last
          // codestream. This does not cause issues, it may affect decisions for
          // copying or not copying user input however.
          bool last_codestream = (strcmp(type, "jxlc") == 0) || (box_size == 0);
          dec->first_codestream_seen = true;
          if (last_codestream) dec->last_codestream_seen = true;
          if (dec->codestream_begin != 0 && dec->codestream.empty()) {
            // We've already seen a codestream part, so it's a stream spanning
            // multiple boxes.
            // We have no choice but to copy contents to the codestream
            // vector to make it a contiguous stream for the C++ decoder.
            // This appends the previous codestream box that we had seen to
            // dec->codestream.
            if (dec->codestream_begin < dec->file_pos) {
              return JXL_API_ERROR("earlier codestream box out of range");
            }
            size_t begin = dec->codestream_begin - dec->file_pos;
            size_t end = dec->codestream_end - dec->file_pos;
            dec->codestream.insert(dec->codestream.end(), *next_in + begin,
                                   *next_in + end);
          }
          dec->codestream_begin = dec->file_pos + pos;
          dec->codestream_end =
              (box_size == 0) ? 0 : (dec->codestream_begin + contents_size);
          // If already appending codestream, append what we have here too
          if (!dec->codestream.empty()) {
            size_t begin = pos;
            size_t end =
                std::min<size_t>(*avail_in, begin + avail_contents_size);
            dec->codestream.insert(dec->codestream.end(), *next_in + begin,
                                   *next_in + end);
            pos += (end - begin);
            dec->file_pos += pos;
            *next_in += pos;
            *avail_in -= pos;
            pos = 0;
            // TODO(lode): check if this should break always instead, and
            // process what we have of the codestream so far, to support
            // progressive decoding, and get events such as basic info faster.
            // The user could have given 1.5 boxes here, and the first one could
            // contain useful parts of codestream that can already be processed.
            // Similar to several other exact avail_size checks. This may not
            // need to be changed here, but instead at the point in this for
            // loop where it returns "NEED_MORE_INPUT", it could instead break
            // and allow decoding what we have of the codestream so far.
            if (*avail_in == 0) break;
          } else {
            // skip only the header, so next_in points to the start of this new
            // codestream part, for the one-shot case where user data is not
            // (yet) copied to dec->codestream.
            dec->file_pos += pos;
            *next_in += pos;
            *avail_in -= pos;
            pos = 0;
            // Update pos to be after the box contents with codestream
            if (avail_contents_size == *avail_in) {
              break;  // the rest is codestream, this loop is done
            }
            pos += avail_contents_size;
          }
        } else if (strcmp(type, "jbrd") == 0) {
          // This is a JPEG reconstruction metadata box.
          // A new box implies that we clear the buffer.
          dec->jpeg_reconstruction_buffer.clear();
          dec->inside_jpeg_reconstruction_box = true;
          if (box_size == 0) {
            dec->jpeg_reconstruction_box_until_eof = true;
          } else {
            dec->jpeg_reconstruction_size = contents_size;
          }
          *next_in += pos;
          *avail_in -= pos;
          JxlDecoderStatus recon_result =
              JxlDecoderProcessJPEGReconstruction(dec, next_in, avail_in);
          pos = 0;
          if (recon_result == JXL_DEC_JPEG_RECONSTRUCTION) {
            // If successful JPEG reconstruction, return the success if the user
            // cares about it, otherwise continue.
            if (dec->events_wanted & recon_result) {
              dec->events_wanted &= ~recon_result;
              return recon_result;
            }
          } else {
            // If anything else, return the result.
            return recon_result;
          }
        } else {
          if (box_size == 0) {
            // Final box with unknown size, but it's not a codestream box, so
            // nothing more to do.
            if (!dec->first_codestream_seen) {
              return JXL_API_ERROR("didn't find any codestream box");
            }
            break;
          }
          if (OutOfBounds(pos, contents_size, size)) {
            // Indicate how many more bytes needed starting from *next_in.
            dec->basic_info_size_hint = InitialBasicInfoSizeHint() + pos +
                                        contents_size - dec->file_pos;
            return JXL_DEC_NEED_MORE_INPUT;
          }
          pos += contents_size;
          if (!(dec->codestream.empty() && dec->first_codestream_seen)) {
            // Last box no longer needed, remove from input.
            dec->file_pos += pos;
            *next_in += pos;
            *avail_in -= pos;
            pos = 0;
          }
        }
      }
    }

    // Size of the codestream, excluding potential boxes that come after it.
    csize = *avail_in;
    if (dec->codestream_end && csize > dec->codestream_end - dec->file_pos) {
      csize = dec->codestream_end - dec->file_pos;
    }
  }

  // Whether we are taking the input directly from the user (oneshot case,
  // without copying bytes), or appending parts of input to dec->codestream
  // (streaming)
  bool detected_streaming = !dec->codestream.empty();
  JxlDecoderStatus result;

  if (detected_streaming) {
    dec->codestream.insert(dec->codestream.end(), *next_in, *next_in + csize);
    dec->file_pos += csize;
    *next_in += csize;
    *avail_in -= csize;
    result = jxl::JxlDecoderProcessInternal(dec, dec->codestream.data(),
                                            dec->codestream.size());
  } else {
    // No data copied to codestream buffer yet, the user input may contain the
    // full codestream.
    result = jxl::JxlDecoderProcessInternal(dec, *next_in, *avail_in);
    // Copy the user's input bytes to the codestream once we are able to and
    // it is needed. Before we got the basic info, we're still parsing the box
    // format instead. If the result is not JXL_DEC_NEED_MORE_INPUT, then
    // there is no reason yet to copy since the user may have a full buffer
    // allowing one-shot. Once JXL_DEC_NEED_MORE_INPUT occured at least once,
    // start copying over the codestream bytes and allow user to free them
    // instead. Next call, detected_streaming will be true.
    if (dec->got_basic_info && result == JXL_DEC_NEED_MORE_INPUT) {
      dec->codestream.insert(dec->codestream.end(), *next_in, *next_in + csize);
      dec->file_pos += csize;
      *next_in += csize;
      *avail_in -= csize;
    }
  }

  return result;
}
``` 

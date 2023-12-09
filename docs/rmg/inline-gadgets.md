### Inline Gadgets

----

Since it's early days, *remote-method-guesser* provides a *ysoserial* integration,
that allows to create *ysoserial* gadgets by using command line parameters passed
within the *rmg* command line. For most situations, this approach is sufficient,
but sometimes support for *inline gadgets* would be useful. With *inline gadgets*
we mean gadgets that are passed e.g. as base64 encoded command line parameter.
This would e.g. allow to use serialization based rmg actions without having the
*ysoserial* even present.

For version *v4.5.0* of remote-method-guesser, *inline gadgets* were part of the
roadmap. However, as it turned out, our considerations on how to implement them
were too naive and at the end, this feature was not implemented at all. In this
document we want to write down some of the problems we encountered, how they could
have been resolved and why we did not follow this path.


### ObjectOutputStream

----

Our first concern was to write the user supplied object to the `ObjectOutputStream`
that one can obtain by calling the `getOutputStream` method on a `StreamRemoteCall`
object. Luckily, remote-method-guesser [already implemented](https://github.com/qtc-de/remote-method-guesser/blob/master/src/eu.tneitzel.rmg/networking/RMIEndpoint.java#L157)
*RMI* calls on such a low level that all this stuff can be accessed quite easily.
Writing the user supplied object is however not that straight forward. We do not
want to deserialize the object, as this would require all gadget libraries to be
present and would lead to payload execution on the executing system. Just writing
the object as bytes to the output stream would also not work, as Java would mark
these bytes as a *byte array* within the output stream and they would not be
interpreted as object on the server side. Tampering with the `ObjectOutputStream`
implementation is therefore required.

One of our first approaches was to subclass `ObjectOutputStream` and to overwrite
the `writeObject` method. We implemented a class `GadgetHolder` that contained
the user supplied gadget as byte array. The custom implementation of `writeObject`
checked whether the current object to be written is a `GadgetHolder` and wrote the
contained byte array directly to the `BlockDataOutputStream` that is part of each
`ObjectOutputStream`.

Since the stream you get from `StreamRemoteCall` is already an `ObjectOutputStream`,
the above mentioned subclass was wrapped essentially an `ObjectOutputStream` wrapped
around an `ObjectOutputStream`. For this to work, it is important to overwrite the
`writeStreamHeader` method, to prevent any stream headers from being written during
the wrapping. Moreover, when writing to `BlockDataOutputStream`, one needs to make
sure that the correct `BlockDataMode` is configured on this stream.

At the end, everything seemed to work well, but remote-method-guessers *gadget canaries*
made us aware, that this implementation is not working for nested objects. When
remote-method-guesser sends a gadget to the application server, it wraps this gadget
into an `Object` array. The first item within this array is the gadget, whereas the second
one is a dynamically created class. The application server will only attempt to deserialize
the second object, if the deserialization of the first one was successful. By checking for 
a `ClassNotFound` exception containing the name of the dynamically created class, successful
gadget deserialization can be verified.

When our subclassed `ObjectOutputStream` attempted to serialize the `Object` array, it used
the custom `writeObject` method. Since `Object[]` is not `GadgetHolder`, it called the superclass
implementation of `writeObject`. For an array however, `writeObject` does not use `writeObject`
to write the contained items to the stream, but uses `writeObject0` instead. This is a private
method and will therefore always use the implementation of the superclass. Nesting `GadgetHolder`
in any kind of other class is therefore not working.

At this point we thought about removing *gadget canaries* when *inline gadgets* are used. But
this seemed not to be the *ideal* solution. After some other failed attempts, we thought that
operating on the underlying stream level would be the best. We associated a unique `SerialVersionUid`
to `GadgetHolder` and padded the user specified gadget with some static prefix and suffix bytes.
Within the `ObjectOutputStream` obtained from `StreamRemoteCall` we replaced the `BlockDataOutputStream`
with a custom stream class. This class checked for the `SerialVersionUid` of `GadgetHolder` and replaced
the object on the stream with the contents of the byte array contained in it's property. Sounds crazy,
but worked with great success - until we discovered the real problems.


### Reference Counting

----

When serializing or deserializing objects, Java tracks certain locations (*handles*) within the stream
that might be referenced at a later point. E.g. if one object is referenced by several fields within a
class, the object only needs to be serialized once and each field can simply point to the already serialized
object. The handles themselves are not contained within the stream, but internally tracked during serialization
or deserialization. References to a handle are part of the stream. Handles are of type `int` and the internal
tracker starts at a value of `0x7e0000`. Each new handle increments this tracker by one.

When creating a payload object using *ysoserial*, it usually contains a lot of these references. This again
causes problems with remote-method-guessers *gadget canaries*. When the actual payload object is wrapped inside
an `Object` array, the `Object` array type gets written first to the stream. Since this type could be referenced
later on, a handle is created for it. The handle count within the stream is no longer in sync with the handle count
that was used by *ysoserial* during the serialization. Therefore, the payload object will not be deserialized
correctly.

This problem could be fixed by shifting the handle references within a payload object with the required value.
Sounds easy, but such an approach would require to reliably identify handle references within a payload object.
A simply match and replace for `0x7e....` would obviously not work, as such a value could appear in other locations
of the stream too. Therefore, one would need to implement a serialization parser like e.g. [SerializationDumper](https://github.com/NickstaDB/SerializationDumper)
and include it into remote-method-guesser. A lot of implementation effort - and at the end, it is still quite hacky.

At this point we decided to drop *gadget canaries* when using *inline gadgets*, but the real problem is yet to come.


### MarshalOutputStream

----

After implementing the above mentioned changes, the deserialization still did not work as expected. Comparing
the network traffic when using the ysoserial integration with the traffic created by an inline gadget revealed
that the former contained additional `TC_NULL` bytes that were missing within the inline gadget. This made us
remember something we already knew, but totally had forgotten.

As it turned out, the assumption that `getOutputStream` on `StreamRemoteCall` returns an `ObjectOutputStream` was
false. What you get is an `ObjectOutput`, but the underlying implementation is a `ConncetionOutputStream` - a class
that extends `MarshalOutputStream`. `MarshalOutputStream` is well known to remote-method-guesser, as this class is
responsible for adding annotations to classes, a feature that allows e.g. remote codebases to work in RMI.

The problem is now that `MarshalOutputStream` **always** writes an annotation to a class. Even if a codebase is not
used and there is noting to annotate, a `null` gets still written. On the other hand, `MarshalInputStream` expects
these annotations also to be present. A gadget created by *ysoserial* however uses a classical `ObjectOutputStream`.
Therefore, these annotation bytes are missing and the `MarshalInputStream` fails to deserialize the object.

This problem could again be overcome in different ways. The easiest approach would probably be to add a `--stream` option
to *ysoserial* that allows to select `MarshalOutputStream` for payload creation. However, this would still require users
to know about this problematic and to use the appropriate option during payload creation. Another option would be to add the
missing `TC_NULL` bytes on the already serialized object, but this would require again a serialization parser.


### Conclusion

----

At the end, we decided against the *inline gadget* feature and will not implement it. If remote-method-guessers
*ysoserial* integration does not work for you, we recommend using the prebuild [docker image](https://github.com/qtc-de/remote-method-guesser/pkgs/container/remote-method-guesser%2Frmg)
that contains *ysoserial* in the *non-slim* versions and should work out of the box.

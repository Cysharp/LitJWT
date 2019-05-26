using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Runtime.CompilerServices;

namespace LitJWT
{
    // allow to lookup by ReadOnlySpan<byte>

    internal class ReadOnlyUtf8StringDictionary<TValue>
    {
        readonly Entry[][] buckets; // immutable array(faster than linkedlist)
        readonly int indexFor;

        public ReadOnlyUtf8StringDictionary(IEnumerable<KeyValuePair<byte[], TValue>> values)
            : this(values, 0.75f)
        {
        }

        public ReadOnlyUtf8StringDictionary(IEnumerable<KeyValuePair<byte[], TValue>> values, float loadFactor)
        {
            var array = values.ToArray();

            var tableSize = CalculateCapacity(array.Length, loadFactor);
            this.buckets = new Entry[tableSize][];
            this.indexFor = buckets.Length - 1;

            foreach (var item in array)
            {
                if (!TryAddInternal(item.Key, item.Value))
                {
                    throw new ArgumentException("Key was already exists. Key:" + item.Key);
                }
            }
        }


        bool TryAddInternal(byte[] key, TValue value)
        {
            var h = unchecked((int)FarmHash.Hash64(key, 0, key.Length));
            var entry = new Entry { Key = key, Value = value };

            var array = buckets[h & (indexFor)];
            if (array == null)
            {
                buckets[h & (indexFor)] = new[] { entry };
            }
            else
            {
                // check duplicate
                for (int i = 0; i < array.Length; i++)
                {
                    var e = array[i].Key;
                    if (new ReadOnlySpan<byte>(key).SequenceEqual(e))
                    {
                        return false;
                    }
                }

                var newArray = new Entry[array.Length + 1];
                Array.Copy(array, newArray, array.Length);
                array = newArray;
                array[array.Length - 1] = entry;
                buckets[h & (indexFor)] = array;
            }

            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool TryGetValue(ReadOnlySpan<byte> key, out TValue value)
        {
            var table = buckets;
            var hash = unchecked((int)FarmHash.Hash64(key));

            var entry = table[hash & indexFor];

            if (entry == null)
            {
                value = default(TValue);
                return false;
            }

            {
                var v = entry[0];
                if (key.SequenceEqual(v.Key))
                {
                    value = v.Value;
                    return true;
                }
            }

            return TryGetValueSlow(entry, key, out value);


        }

        bool TryGetValueSlow(Entry[] entry, ReadOnlySpan<byte> key, out TValue value)
        {
            for (int i = 1; i < entry.Length; i++)
            {
                var v = entry[i];
                if (key.SequenceEqual(v.Key))
                {
                    value = v.Value;
                    return true;
                }
            }

            value = default(TValue);
            return false;
        }

        static int CalculateCapacity(int collectionSize, float loadFactor)
        {
            var size = (int)(((float)collectionSize) / loadFactor);

            size--;
            size |= size >> 1;
            size |= size >> 2;
            size |= size >> 4;
            size |= size >> 8;
            size |= size >> 16;
            size += 1;

            if (size < 8)
            {
                size = 8;
            }
            return size;
        }

        struct Entry
        {
            public byte[] Key;
            public TValue Value;

            // for debugging
            public override string ToString()
            {
                return "(" + Encoding.UTF8.GetString(Key) + ", " + Value + ")";
            }
        }
    }
}

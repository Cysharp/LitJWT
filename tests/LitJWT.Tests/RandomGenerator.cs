using System;
using RandomFixtureKit;

namespace LitJWT.Tests
{
    public class RandomByteArrayGenerator : RandomFixtureKit.IGenerator
    {
        public Type Type => typeof(byte[]);

        public object Generate(in GenerationContext context)
        {
            var rand = RandomProvider.GetRandom();
            var length = rand.Next(0, 33);
            var byteArray = new byte[length];
            for (int i = 0; i < byteArray.Length; i++)
            {
                byteArray[i] = (byte)rand.Next(0, byte.MaxValue);
            }

            return byteArray;
        }
    }

    public class RandomByteArrayResolver : RandomFixtureKit.IGeneratorResolver
    {
        public static RandomFixtureKit.IGeneratorResolver Default = new RandomByteArrayResolver();

        public IGenerator GetGenerator(Type type)
        {
            if (type == typeof(byte[]))
            {
                return new RandomByteArrayGenerator();
            }
            return null;
        }
    }
}

using System.Linq;

namespace NoEdgeCrypto.Tests
{
    class Foo
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string[] Misc { get; set; }

        public override bool Equals(object obj)
        {
            return obj != null && obj is Foo && ((Foo)obj).Id == Id && ((Foo)obj).Name == Name 
                && (
                    (((Foo)obj).Misc == null && Misc == null)
                    || (((Foo)obj).Misc != null && Misc != null && ((Foo)obj).Misc.SequenceEqual(Misc))
                );
        }

        public override int GetHashCode()
        {
            return (Id + Name + string.Join('|', Misc ?? new string[0])).GetHashCode();
        }
    }
}

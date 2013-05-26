/*
 * Created on 25 mrt 2010
 */

package craterstudio.bytes;

public interface KeyValueSet
{
   public byte[] put(byte[] key, byte[] value);

   public byte[] get(byte[] key);

   public byte[] remove(byte[] key);
}

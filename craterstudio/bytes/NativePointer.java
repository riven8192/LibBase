/*
 * Created on 27 feb 2009
 */

package craterstudio.bytes;

public class NativePointer
{
   public long pntr;

   public NativePointer(long pntr)
   {
      this.pntr = pntr;
   }

   // byte

   public void bput(int off, byte value)
   {
      Native.bput(this.pntr + off, value);
   }

   public byte bget(int off)
   {
      return Native.bget(this.pntr + off);
   }

   // short

   public void sput(int off, short value)
   {
      Native.sput(this.pntr + off, value);
   }

   public short sget(int off)
   {
      return Native.sget(this.pntr + off);
   }

   // int

   public void iput(int off, int value)
   {
      Native.iput(this.pntr + off, value);
   }

   public int iget(int off)
   {
      return Native.iget(this.pntr + off);
   }

   // long

   public void lput(int off, long value)
   {
      Native.lput(this.pntr + off, value);
   }

   public long lget(int off)
   {
      return Native.lget(this.pntr + off);
   }

   // float

   public void fput(int off, float value)
   {
      Native.fput(this.pntr + off, value);
   }

   public float fget(int off)
   {
      return Native.fget(this.pntr + off);
   }

   // double

   public void dput(int off, double value)
   {
      Native.dput(this.pntr + off, value);
   }

   public double dget(int off)
   {
      return Native.dget(this.pntr + off);
   }
}

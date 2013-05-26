/*
 * Created on 27 feb 2009
 */

package craterstudio.bytes;

import java.nio.BufferOverflowException;

public class NativeBuffer
{
   public long pntr;
   public int  len;

   public NativeBuffer(long pntr, int len)
   {
      this.pntr = pntr;
      this.len = len;
   }

   // byte

   public void bput(int off, byte value)
   {
      this.checkIndex1(off);
      Native.bput(this.pntr + off, value);
   }

   public byte bget(int off)
   {
      this.checkIndex1(off);
      return Native.bget(this.pntr + off);
   }

   // short

   public void sput(int off, short value)
   {
      this.checkIndex2(off);
      Native.sput(this.pntr + off, value);
   }

   public short sget(int off)
   {
      this.checkIndex2(off);
      return Native.sget(this.pntr + off);
   }

   // int

   public void iput(int off, int value)
   {
      this.checkIndex4(off);
      Native.iput(this.pntr + off, value);
   }

   public int iget(int off)
   {
      this.checkIndex4(off);
      return Native.iget(this.pntr + off);
   }

   // long

   public void lput(int off, long value)
   {
      this.checkIndex8(off);
      Native.lput(this.pntr + off, value);
   }

   public long lget(int off)
   {
      this.checkIndex8(off);
      return Native.lget(this.pntr + off);
   }

   // float

   public void fput(int off, float value)
   {
      this.checkIndex4(off);
      Native.fput(this.pntr + off, value);
   }

   public float fget(int off)
   {
      this.checkIndex4(off);
      return Native.fget(this.pntr + off);
   }

   // double

   public void dput(int off, double value)
   {
      this.checkIndex8(off);
      Native.dput(this.pntr + off, value);
   }

   public double dget(int off)
   {
      this.checkIndex8(off);
      return Native.dget(this.pntr + off);
   }

   // index checks

   private final void checkIndex1(int off)
   {
      if (off < 0 || off + 1 > this.len)
      {
         throw new BufferOverflowException();
      }
   }

   private final void checkIndex2(int off)
   {
      if (off < 0 || off + 2 > this.len)
      {
         throw new BufferOverflowException();
      }
   }

   private final void checkIndex4(int off)
   {
      if (off < 0 || off + 4 > this.len)
      {
         throw new BufferOverflowException();
      }
   }

   private final void checkIndex8(int off)
   {
      if (off < 0 || off + 8 > this.len)
      {
         throw new BufferOverflowException();
      }
   }
}

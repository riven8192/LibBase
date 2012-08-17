package craterstudio.misc;

public class PerlinLayer
{
   public static PerlinLayer createByRange(PerlinNoise noise, int octaves, float range)
   {
      return new PerlinLayer(noise, octaves, 1.0f / range);
   }
   
   /**
    * CONSTRUCTORS
    */

   private final PerlinNoise[] noise;
   private final int           octaves;

   public PerlinLayer(PerlinNoise noise, int octaves, float detail)
   {
      this(new PerlinNoise[] { noise }, octaves, detail);
   }

   public PerlinLayer(PerlinNoise[] noise, int octaves, float detail)
   {
      this.noise = noise;
      this.octaves = octaves;
      this.setDetail(detail);
   }

   /**
    * 
    */

   private float xDetail, yDetail, zDetail;

   public final void setDetail(float detail)
   {
      this.setDetail(detail, detail, detail);
   }

   public final void setDetail(float xDetail, float yDetail, float zDetail)
   {
      this.xDetail = xDetail;
      this.yDetail = yDetail;
      this.zDetail = zDetail;
   }

   /**
    * SMOOTH
    */

   public final float getSmooth1D(float x)
   {
      float x0 = x * xDetail;
      float height = 0.0f;

      for (int i = 0; i < noise.length; i++)
         for (int octave = 1; octave <= octaves; octave++)
            height += noise[i].noise1D(x0, octave);

      return height;
   }

   public final float getSmooth2D(float x, float y)
   {
      float x0 = x * xDetail;
      float y0 = y * yDetail;
      float height = 0.0f;

      for (int i = 0; i < noise.length; i++)
         for (int octave = 1; octave <= octaves; octave++)
            height += noise[i].noise2D(x0, y0, octave);

      return height;
   }

   public final float getSmooth3D(float x, float y, float z)
   {
      float x0 = x * xDetail;
      float y0 = y * yDetail;
      float z0 = z * zDetail;
      float height = 0.0f;

      for (int i = 0; i < noise.length; i++)
         for (int octave = 1; octave <= octaves; octave++)
            height += noise[i].noise3D(x0, y0, z0, octave);

      return height;
   }

   /**
    * ROUGH
    */

   public final float getRough1D(float x)
   {
      float x0 = x * xDetail;
      float height = 0.0f;

      for (int i = 0; i < noise.length; i++)
      {
         float h = 0.0f;
         for (int octave = 1; octave <= octaves; octave++)
            h += noise[i].noise1D(x0, octave);
         if (h < 0.0f)
            h *= -1.0f;
         height += h;
      }

      return height;
   }

   public final float getRough2D(float x, float y)
   {
      float x0 = x * xDetail;
      float y0 = y * yDetail;
      float height = 0.0f;

      for (int i = 0; i < noise.length; i++)
      {
         float h = 0.0f;
         for (int octave = 1; octave <= octaves; octave++)
            h += noise[i].noise2D(x0, y0, octave);
         if (h < 0.0f)
            h *= -1.0f;
         height += h;
      }

      return height;
   }

   public final float getRough3D(float x, float y, float z)
   {
      float x0 = x * xDetail;
      float y0 = y * yDetail;
      float z0 = z * zDetail;
      float height = 0.0f;

      for (int i = 0; i < noise.length; i++)
      {
         float h = 0.0f;
         for (int octave = 1; octave <= octaves; octave++)
            h += noise[i].noise3D(x0, y0, z0, octave);
         if (h < 0.0f)
            h *= -1.0f;
         height += h;
      }

      return height;
   }
}
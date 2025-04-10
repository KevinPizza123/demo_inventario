PGDMP  2    "                }            demo_militar    16.8    16.8 4    N           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            O           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            P           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            Q           1262    16398    demo_militar    DATABASE     r   CREATE DATABASE demo_militar WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'es-EC';
    DROP DATABASE demo_militar;
                postgres    false            �            1259    16465    imagenes    TABLE     �   CREATE TABLE public.imagenes (
    id integer NOT NULL,
    nombrearchivo character varying(255) NOT NULL,
    productoid integer
);
    DROP TABLE public.imagenes;
       public         heap    postgres    false            �            1259    16464    imagenes_id_seq    SEQUENCE     �   CREATE SEQUENCE public.imagenes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.imagenes_id_seq;
       public          postgres    false    226            R           0    0    imagenes_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.imagenes_id_seq OWNED BY public.imagenes.id;
          public          postgres    false    225            �            1259    16439 
   inventario    TABLE     �   CREATE TABLE public.inventario (
    id integer NOT NULL,
    productoid integer NOT NULL,
    localid integer NOT NULL,
    cantidad integer NOT NULL
);
    DROP TABLE public.inventario;
       public         heap    postgres    false            �            1259    16438    inventario_id_seq    SEQUENCE     �   CREATE SEQUENCE public.inventario_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.inventario_id_seq;
       public          postgres    false    222            S           0    0    inventario_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.inventario_id_seq OWNED BY public.inventario.id;
          public          postgres    false    221            �            1259    16400    locales    TABLE     �   CREATE TABLE public.locales (
    id integer NOT NULL,
    nombre character varying(255) NOT NULL,
    direccion character varying(255) NOT NULL,
    responsablenombre character varying(255)
);
    DROP TABLE public.locales;
       public         heap    postgres    false            �            1259    16399    locales_id_seq    SEQUENCE     �   CREATE SEQUENCE public.locales_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 %   DROP SEQUENCE public.locales_id_seq;
       public          postgres    false    216            T           0    0    locales_id_seq    SEQUENCE OWNED BY     A   ALTER SEQUENCE public.locales_id_seq OWNED BY public.locales.id;
          public          postgres    false    215            �            1259    16425 	   productos    TABLE     �   CREATE TABLE public.productos (
    id integer NOT NULL,
    nombre character varying(255) NOT NULL,
    precio numeric NOT NULL,
    stock integer NOT NULL,
    localid integer,
    descripcion text
);
    DROP TABLE public.productos;
       public         heap    postgres    false            �            1259    16424    productos_id_seq    SEQUENCE     �   CREATE SEQUENCE public.productos_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.productos_id_seq;
       public          postgres    false    220            U           0    0    productos_id_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.productos_id_seq OWNED BY public.productos.id;
          public          postgres    false    219            �            1259    16456    proveedores    TABLE     �   CREATE TABLE public.proveedores (
    id integer NOT NULL,
    nombre character varying(255) NOT NULL,
    contacto character varying(255) NOT NULL,
    telefono character varying(255) NOT NULL,
    correo character varying(255)
);
    DROP TABLE public.proveedores;
       public         heap    postgres    false            �            1259    16455    proveedores_id_seq    SEQUENCE     �   CREATE SEQUENCE public.proveedores_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.proveedores_id_seq;
       public          postgres    false    224            V           0    0    proveedores_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.proveedores_id_seq OWNED BY public.proveedores.id;
          public          postgres    false    223            �            1259    16409    usuarios    TABLE     .  CREATE TABLE public.usuarios (
    id integer NOT NULL,
    nombre character varying(255) NOT NULL,
    apellido character varying(255) NOT NULL,
    correo character varying(255) NOT NULL,
    contrasena character varying(255) NOT NULL,
    rol character varying(255) NOT NULL,
    localid integer
);
    DROP TABLE public.usuarios;
       public         heap    postgres    false            �            1259    16408    usuarios_id_seq    SEQUENCE     �   CREATE SEQUENCE public.usuarios_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.usuarios_id_seq;
       public          postgres    false    218            W           0    0    usuarios_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.usuarios_id_seq OWNED BY public.usuarios.id;
          public          postgres    false    217            �           2604    16468    imagenes id    DEFAULT     j   ALTER TABLE ONLY public.imagenes ALTER COLUMN id SET DEFAULT nextval('public.imagenes_id_seq'::regclass);
 :   ALTER TABLE public.imagenes ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    225    226    226            �           2604    16442    inventario id    DEFAULT     n   ALTER TABLE ONLY public.inventario ALTER COLUMN id SET DEFAULT nextval('public.inventario_id_seq'::regclass);
 <   ALTER TABLE public.inventario ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    222    221    222            �           2604    16403 
   locales id    DEFAULT     h   ALTER TABLE ONLY public.locales ALTER COLUMN id SET DEFAULT nextval('public.locales_id_seq'::regclass);
 9   ALTER TABLE public.locales ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    216    215    216            �           2604    16428    productos id    DEFAULT     l   ALTER TABLE ONLY public.productos ALTER COLUMN id SET DEFAULT nextval('public.productos_id_seq'::regclass);
 ;   ALTER TABLE public.productos ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    219    220    220            �           2604    16459    proveedores id    DEFAULT     p   ALTER TABLE ONLY public.proveedores ALTER COLUMN id SET DEFAULT nextval('public.proveedores_id_seq'::regclass);
 =   ALTER TABLE public.proveedores ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    223    224    224            �           2604    16412    usuarios id    DEFAULT     j   ALTER TABLE ONLY public.usuarios ALTER COLUMN id SET DEFAULT nextval('public.usuarios_id_seq'::regclass);
 :   ALTER TABLE public.usuarios ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    217    218    218            K          0    16465    imagenes 
   TABLE DATA           A   COPY public.imagenes (id, nombrearchivo, productoid) FROM stdin;
    public          postgres    false    226   q:       G          0    16439 
   inventario 
   TABLE DATA           G   COPY public.inventario (id, productoid, localid, cantidad) FROM stdin;
    public          postgres    false    222   �:       A          0    16400    locales 
   TABLE DATA           K   COPY public.locales (id, nombre, direccion, responsablenombre) FROM stdin;
    public          postgres    false    216   �:       E          0    16425 	   productos 
   TABLE DATA           T   COPY public.productos (id, nombre, precio, stock, localid, descripcion) FROM stdin;
    public          postgres    false    220   �:       I          0    16456    proveedores 
   TABLE DATA           M   COPY public.proveedores (id, nombre, contacto, telefono, correo) FROM stdin;
    public          postgres    false    224   �:       C          0    16409    usuarios 
   TABLE DATA           Z   COPY public.usuarios (id, nombre, apellido, correo, contrasena, rol, localid) FROM stdin;
    public          postgres    false    218   ;       X           0    0    imagenes_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.imagenes_id_seq', 9, true);
          public          postgres    false    225            Y           0    0    inventario_id_seq    SEQUENCE SET     @   SELECT pg_catalog.setval('public.inventario_id_seq', 1, false);
          public          postgres    false    221            Z           0    0    locales_id_seq    SEQUENCE SET     <   SELECT pg_catalog.setval('public.locales_id_seq', 1, true);
          public          postgres    false    215            [           0    0    productos_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.productos_id_seq', 9, true);
          public          postgres    false    219            \           0    0    proveedores_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.proveedores_id_seq', 1, false);
          public          postgres    false    223            ]           0    0    usuarios_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.usuarios_id_seq', 1, true);
          public          postgres    false    217            �           2606    16470    imagenes imagenes_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.imagenes
    ADD CONSTRAINT imagenes_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.imagenes DROP CONSTRAINT imagenes_pkey;
       public            postgres    false    226            �           2606    16444    inventario inventario_pkey 
   CONSTRAINT     X   ALTER TABLE ONLY public.inventario
    ADD CONSTRAINT inventario_pkey PRIMARY KEY (id);
 D   ALTER TABLE ONLY public.inventario DROP CONSTRAINT inventario_pkey;
       public            postgres    false    222            �           2606    16407    locales locales_pkey 
   CONSTRAINT     R   ALTER TABLE ONLY public.locales
    ADD CONSTRAINT locales_pkey PRIMARY KEY (id);
 >   ALTER TABLE ONLY public.locales DROP CONSTRAINT locales_pkey;
       public            postgres    false    216            �           2606    16432    productos productos_pkey 
   CONSTRAINT     V   ALTER TABLE ONLY public.productos
    ADD CONSTRAINT productos_pkey PRIMARY KEY (id);
 B   ALTER TABLE ONLY public.productos DROP CONSTRAINT productos_pkey;
       public            postgres    false    220            �           2606    16463    proveedores proveedores_pkey 
   CONSTRAINT     Z   ALTER TABLE ONLY public.proveedores
    ADD CONSTRAINT proveedores_pkey PRIMARY KEY (id);
 F   ALTER TABLE ONLY public.proveedores DROP CONSTRAINT proveedores_pkey;
       public            postgres    false    224            �           2606    16418    usuarios usuarios_correo_key 
   CONSTRAINT     Y   ALTER TABLE ONLY public.usuarios
    ADD CONSTRAINT usuarios_correo_key UNIQUE (correo);
 F   ALTER TABLE ONLY public.usuarios DROP CONSTRAINT usuarios_correo_key;
       public            postgres    false    218            �           2606    16416    usuarios usuarios_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.usuarios
    ADD CONSTRAINT usuarios_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.usuarios DROP CONSTRAINT usuarios_pkey;
       public            postgres    false    218            �           2606    16471 !   imagenes imagenes_productoid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.imagenes
    ADD CONSTRAINT imagenes_productoid_fkey FOREIGN KEY (productoid) REFERENCES public.productos(id);
 K   ALTER TABLE ONLY public.imagenes DROP CONSTRAINT imagenes_productoid_fkey;
       public          postgres    false    226    220    4773            �           2606    16450 "   inventario inventario_localid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.inventario
    ADD CONSTRAINT inventario_localid_fkey FOREIGN KEY (localid) REFERENCES public.locales(id);
 L   ALTER TABLE ONLY public.inventario DROP CONSTRAINT inventario_localid_fkey;
       public          postgres    false    216    4767    222            �           2606    16445 %   inventario inventario_productoid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.inventario
    ADD CONSTRAINT inventario_productoid_fkey FOREIGN KEY (productoid) REFERENCES public.productos(id);
 O   ALTER TABLE ONLY public.inventario DROP CONSTRAINT inventario_productoid_fkey;
       public          postgres    false    4773    220    222            �           2606    16433     productos productos_localid_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.productos
    ADD CONSTRAINT productos_localid_fkey FOREIGN KEY (localid) REFERENCES public.locales(id);
 J   ALTER TABLE ONLY public.productos DROP CONSTRAINT productos_localid_fkey;
       public          postgres    false    216    220    4767            �           2606    16419    usuarios usuarios_localid_fkey    FK CONSTRAINT        ALTER TABLE ONLY public.usuarios
    ADD CONSTRAINT usuarios_localid_fkey FOREIGN KEY (localid) REFERENCES public.locales(id);
 H   ALTER TABLE ONLY public.usuarios DROP CONSTRAINT usuarios_localid_fkey;
       public          postgres    false    218    4767    216            K      x������ � �      G      x������ � �      A   &   x�3�t�ON�tN�+)�WpW05S�������� 7`      E      x������ � �      I      x������ � �      C   o   x�3���L/M��tL�����s�L�s3s���s9U��T�T++\+J\˓RC�=S��
���Lܝ2��\"�L
C��˽�M�
M�J��R�8����q��qqq u!�     
PGDMP  ,                    |            ProjectTEST    15.7    16.3 [    P           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            Q           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            R           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            S           1262    16398    ProjectTEST    DATABASE        CREATE DATABASE "ProjectTEST" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'Thai_Thailand.874';
    DROP DATABASE "ProjectTEST";
                postgres    false            �            1259    16644    device    TABLE     �   CREATE TABLE public.device (
    device_id integer NOT NULL,
    device_name character varying(100),
    device_description text,
    device_availability boolean,
    device_approve boolean
);
    DROP TABLE public.device;
       public         heap    postgres    false            �            1259    16643    device_device_id_seq    SEQUENCE     �   CREATE SEQUENCE public.device_device_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 +   DROP SEQUENCE public.device_device_id_seq;
       public          postgres    false    231            T           0    0    device_device_id_seq    SEQUENCE OWNED BY     M   ALTER SEQUENCE public.device_device_id_seq OWNED BY public.device.device_id;
          public          postgres    false    230            �            1259    16616    loan_detail    TABLE     �   CREATE TABLE public.loan_detail (
    loan_id integer NOT NULL,
    transaction_id integer NOT NULL,
    device_id integer NOT NULL,
    loan_date timestamp with time zone,
    location_to_loan character varying(100)
);
    DROP TABLE public.loan_detail;
       public         heap    postgres    false            �            1259    16625    loan_detail_device_id_seq    SEQUENCE     �   CREATE SEQUENCE public.loan_detail_device_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.loan_detail_device_id_seq;
       public          postgres    false    223            U           0    0    loan_detail_device_id_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.loan_detail_device_id_seq OWNED BY public.loan_detail.device_id;
          public          postgres    false    225            �            1259    16615    loan_detail_loan_id_seq    SEQUENCE     �   CREATE SEQUENCE public.loan_detail_loan_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.loan_detail_loan_id_seq;
       public          postgres    false    223            V           0    0    loan_detail_loan_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.loan_detail_loan_id_seq OWNED BY public.loan_detail.loan_id;
          public          postgres    false    222            �            1259    16620    loan_detail_transaction_id_seq    SEQUENCE     �   CREATE SEQUENCE public.loan_detail_transaction_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 5   DROP SEQUENCE public.loan_detail_transaction_id_seq;
       public          postgres    false    223            W           0    0    loan_detail_transaction_id_seq    SEQUENCE OWNED BY     a   ALTER SEQUENCE public.loan_detail_transaction_id_seq OWNED BY public.loan_detail.transaction_id;
          public          postgres    false    224            �            1259    16633    return_detail    TABLE     �   CREATE TABLE public.return_detail (
    return_id integer NOT NULL,
    transaction_id integer NOT NULL,
    device_id integer NOT NULL,
    return_date timestamp with time zone,
    location_to_return character varying(100)
);
 !   DROP TABLE public.return_detail;
       public         heap    postgres    false            �            1259    16632    return_detail_device_id_seq    SEQUENCE     �   CREATE SEQUENCE public.return_detail_device_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 2   DROP SEQUENCE public.return_detail_device_id_seq;
       public          postgres    false    229            X           0    0    return_detail_device_id_seq    SEQUENCE OWNED BY     [   ALTER SEQUENCE public.return_detail_device_id_seq OWNED BY public.return_detail.device_id;
          public          postgres    false    228            �            1259    16630    return_detail_return_id_seq    SEQUENCE     �   CREATE SEQUENCE public.return_detail_return_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 2   DROP SEQUENCE public.return_detail_return_id_seq;
       public          postgres    false    229            Y           0    0    return_detail_return_id_seq    SEQUENCE OWNED BY     [   ALTER SEQUENCE public.return_detail_return_id_seq OWNED BY public.return_detail.return_id;
          public          postgres    false    226            �            1259    16631     return_detail_transaction_id_seq    SEQUENCE     �   CREATE SEQUENCE public.return_detail_transaction_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 7   DROP SEQUENCE public.return_detail_transaction_id_seq;
       public          postgres    false    229            Z           0    0     return_detail_transaction_id_seq    SEQUENCE OWNED BY     e   ALTER SEQUENCE public.return_detail_transaction_id_seq OWNED BY public.return_detail.transaction_id;
          public          postgres    false    227            �            1259    16655    room    TABLE     z   CREATE TABLE public.room (
    room_id integer NOT NULL,
    device_id integer NOT NULL,
    room_availability boolean
);
    DROP TABLE public.room;
       public         heap    postgres    false            �            1259    16654    room_device_id_seq    SEQUENCE     �   CREATE SEQUENCE public.room_device_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 )   DROP SEQUENCE public.room_device_id_seq;
       public          postgres    false    234            [           0    0    room_device_id_seq    SEQUENCE OWNED BY     I   ALTER SEQUENCE public.room_device_id_seq OWNED BY public.room.device_id;
          public          postgres    false    233            �            1259    16653    room_room_id_seq    SEQUENCE     �   CREATE SEQUENCE public.room_room_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 '   DROP SEQUENCE public.room_room_id_seq;
       public          postgres    false    234            \           0    0    room_room_id_seq    SEQUENCE OWNED BY     E   ALTER SEQUENCE public.room_room_id_seq OWNED BY public.room.room_id;
          public          postgres    false    232            �            1259    16592    transaction    TABLE     �  CREATE TABLE public.transaction (
    transaction_id integer NOT NULL,
    user_id integer NOT NULL,
    device_id integer NOT NULL,
    loan_id integer NOT NULL,
    return_id integer NOT NULL,
    loan_date_setting timestamp with time zone,
    return_date_setting timestamp with time zone,
    due_date_setting timestamp with time zone,
    transaction_history text,
    transaction_report text
);
    DROP TABLE public.transaction;
       public         heap    postgres    false            �            1259    16591    transaction_device_id_seq    SEQUENCE     �   CREATE SEQUENCE public.transaction_device_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.transaction_device_id_seq;
       public          postgres    false    219            ]           0    0    transaction_device_id_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.transaction_device_id_seq OWNED BY public.transaction.device_id;
          public          postgres    false    218            �            1259    16601    transaction_loan_id_seq    SEQUENCE     �   CREATE SEQUENCE public.transaction_loan_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.transaction_loan_id_seq;
       public          postgres    false    219            ^           0    0    transaction_loan_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.transaction_loan_id_seq OWNED BY public.transaction.loan_id;
          public          postgres    false    220            �            1259    16607    transaction_return_id_seq    SEQUENCE     �   CREATE SEQUENCE public.transaction_return_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 0   DROP SEQUENCE public.transaction_return_id_seq;
       public          postgres    false    219            _           0    0    transaction_return_id_seq    SEQUENCE OWNED BY     W   ALTER SEQUENCE public.transaction_return_id_seq OWNED BY public.transaction.return_id;
          public          postgres    false    221            �            1259    16589    transaction_transaction_id_seq    SEQUENCE     �   CREATE SEQUENCE public.transaction_transaction_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 5   DROP SEQUENCE public.transaction_transaction_id_seq;
       public          postgres    false    219            `           0    0    transaction_transaction_id_seq    SEQUENCE OWNED BY     a   ALTER SEQUENCE public.transaction_transaction_id_seq OWNED BY public.transaction.transaction_id;
          public          postgres    false    216            �            1259    16590    transaction_user_id_seq    SEQUENCE     �   CREATE SEQUENCE public.transaction_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 .   DROP SEQUENCE public.transaction_user_id_seq;
       public          postgres    false    219            a           0    0    transaction_user_id_seq    SEQUENCE OWNED BY     S   ALTER SEQUENCE public.transaction_user_id_seq OWNED BY public.transaction.user_id;
          public          postgres    false    217            �            1259    16399    users    TABLE       CREATE TABLE public.users (
    user_id integer NOT NULL,
    user_firstname character varying(100),
    user_lastname character varying(100),
    user_email character varying(100),
    user_password character varying(100),
    user_role character varying(100)
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    16573    users_user_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 (   DROP SEQUENCE public.users_user_id_seq;
       public          postgres    false    214            b           0    0    users_user_id_seq    SEQUENCE OWNED BY     G   ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;
          public          postgres    false    215            �           2604    16647    device device_id    DEFAULT     t   ALTER TABLE ONLY public.device ALTER COLUMN device_id SET DEFAULT nextval('public.device_device_id_seq'::regclass);
 ?   ALTER TABLE public.device ALTER COLUMN device_id DROP DEFAULT;
       public          postgres    false    230    231    231            �           2604    16619    loan_detail loan_id    DEFAULT     z   ALTER TABLE ONLY public.loan_detail ALTER COLUMN loan_id SET DEFAULT nextval('public.loan_detail_loan_id_seq'::regclass);
 B   ALTER TABLE public.loan_detail ALTER COLUMN loan_id DROP DEFAULT;
       public          postgres    false    223    222    223            �           2604    16621    loan_detail transaction_id    DEFAULT     �   ALTER TABLE ONLY public.loan_detail ALTER COLUMN transaction_id SET DEFAULT nextval('public.loan_detail_transaction_id_seq'::regclass);
 I   ALTER TABLE public.loan_detail ALTER COLUMN transaction_id DROP DEFAULT;
       public          postgres    false    224    223            �           2604    16626    loan_detail device_id    DEFAULT     ~   ALTER TABLE ONLY public.loan_detail ALTER COLUMN device_id SET DEFAULT nextval('public.loan_detail_device_id_seq'::regclass);
 D   ALTER TABLE public.loan_detail ALTER COLUMN device_id DROP DEFAULT;
       public          postgres    false    225    223            �           2604    16636    return_detail return_id    DEFAULT     �   ALTER TABLE ONLY public.return_detail ALTER COLUMN return_id SET DEFAULT nextval('public.return_detail_return_id_seq'::regclass);
 F   ALTER TABLE public.return_detail ALTER COLUMN return_id DROP DEFAULT;
       public          postgres    false    229    226    229            �           2604    16637    return_detail transaction_id    DEFAULT     �   ALTER TABLE ONLY public.return_detail ALTER COLUMN transaction_id SET DEFAULT nextval('public.return_detail_transaction_id_seq'::regclass);
 K   ALTER TABLE public.return_detail ALTER COLUMN transaction_id DROP DEFAULT;
       public          postgres    false    229    227    229            �           2604    16638    return_detail device_id    DEFAULT     �   ALTER TABLE ONLY public.return_detail ALTER COLUMN device_id SET DEFAULT nextval('public.return_detail_device_id_seq'::regclass);
 F   ALTER TABLE public.return_detail ALTER COLUMN device_id DROP DEFAULT;
       public          postgres    false    229    228    229            �           2604    16658    room room_id    DEFAULT     l   ALTER TABLE ONLY public.room ALTER COLUMN room_id SET DEFAULT nextval('public.room_room_id_seq'::regclass);
 ;   ALTER TABLE public.room ALTER COLUMN room_id DROP DEFAULT;
       public          postgres    false    232    234    234            �           2604    16659    room device_id    DEFAULT     p   ALTER TABLE ONLY public.room ALTER COLUMN device_id SET DEFAULT nextval('public.room_device_id_seq'::regclass);
 =   ALTER TABLE public.room ALTER COLUMN device_id DROP DEFAULT;
       public          postgres    false    233    234    234            �           2604    16595    transaction transaction_id    DEFAULT     �   ALTER TABLE ONLY public.transaction ALTER COLUMN transaction_id SET DEFAULT nextval('public.transaction_transaction_id_seq'::regclass);
 I   ALTER TABLE public.transaction ALTER COLUMN transaction_id DROP DEFAULT;
       public          postgres    false    219    216    219            �           2604    16596    transaction user_id    DEFAULT     z   ALTER TABLE ONLY public.transaction ALTER COLUMN user_id SET DEFAULT nextval('public.transaction_user_id_seq'::regclass);
 B   ALTER TABLE public.transaction ALTER COLUMN user_id DROP DEFAULT;
       public          postgres    false    217    219    219            �           2604    16597    transaction device_id    DEFAULT     ~   ALTER TABLE ONLY public.transaction ALTER COLUMN device_id SET DEFAULT nextval('public.transaction_device_id_seq'::regclass);
 D   ALTER TABLE public.transaction ALTER COLUMN device_id DROP DEFAULT;
       public          postgres    false    219    218    219            �           2604    16602    transaction loan_id    DEFAULT     z   ALTER TABLE ONLY public.transaction ALTER COLUMN loan_id SET DEFAULT nextval('public.transaction_loan_id_seq'::regclass);
 B   ALTER TABLE public.transaction ALTER COLUMN loan_id DROP DEFAULT;
       public          postgres    false    220    219            �           2604    16608    transaction return_id    DEFAULT     ~   ALTER TABLE ONLY public.transaction ALTER COLUMN return_id SET DEFAULT nextval('public.transaction_return_id_seq'::regclass);
 D   ALTER TABLE public.transaction ALTER COLUMN return_id DROP DEFAULT;
       public          postgres    false    221    219            �           2604    16600    users user_id    DEFAULT     n   ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);
 <   ALTER TABLE public.users ALTER COLUMN user_id DROP DEFAULT;
       public          postgres    false    215    214            J          0    16644    device 
   TABLE DATA           q   COPY public.device (device_id, device_name, device_description, device_availability, device_approve) FROM stdin;
    public          postgres    false    231   �l       B          0    16616    loan_detail 
   TABLE DATA           f   COPY public.loan_detail (loan_id, transaction_id, device_id, loan_date, location_to_loan) FROM stdin;
    public          postgres    false    223   �l       H          0    16633    return_detail 
   TABLE DATA           n   COPY public.return_detail (return_id, transaction_id, device_id, return_date, location_to_return) FROM stdin;
    public          postgres    false    229   �l       M          0    16655    room 
   TABLE DATA           E   COPY public.room (room_id, device_id, room_availability) FROM stdin;
    public          postgres    false    234   m       >          0    16592    transaction 
   TABLE DATA           �   COPY public.transaction (transaction_id, user_id, device_id, loan_id, return_id, loan_date_setting, return_date_setting, due_date_setting, transaction_history, transaction_report) FROM stdin;
    public          postgres    false    219   8m       9          0    16399    users 
   TABLE DATA           m   COPY public.users (user_id, user_firstname, user_lastname, user_email, user_password, user_role) FROM stdin;
    public          postgres    false    214   Um       c           0    0    device_device_id_seq    SEQUENCE SET     C   SELECT pg_catalog.setval('public.device_device_id_seq', 1, false);
          public          postgres    false    230            d           0    0    loan_detail_device_id_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('public.loan_detail_device_id_seq', 1, false);
          public          postgres    false    225            e           0    0    loan_detail_loan_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.loan_detail_loan_id_seq', 1, false);
          public          postgres    false    222            f           0    0    loan_detail_transaction_id_seq    SEQUENCE SET     M   SELECT pg_catalog.setval('public.loan_detail_transaction_id_seq', 1, false);
          public          postgres    false    224            g           0    0    return_detail_device_id_seq    SEQUENCE SET     J   SELECT pg_catalog.setval('public.return_detail_device_id_seq', 1, false);
          public          postgres    false    228            h           0    0    return_detail_return_id_seq    SEQUENCE SET     J   SELECT pg_catalog.setval('public.return_detail_return_id_seq', 1, false);
          public          postgres    false    226            i           0    0     return_detail_transaction_id_seq    SEQUENCE SET     O   SELECT pg_catalog.setval('public.return_detail_transaction_id_seq', 1, false);
          public          postgres    false    227            j           0    0    room_device_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.room_device_id_seq', 1, false);
          public          postgres    false    233            k           0    0    room_room_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.room_room_id_seq', 1, false);
          public          postgres    false    232            l           0    0    transaction_device_id_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('public.transaction_device_id_seq', 1, false);
          public          postgres    false    218            m           0    0    transaction_loan_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.transaction_loan_id_seq', 1, false);
          public          postgres    false    220            n           0    0    transaction_return_id_seq    SEQUENCE SET     H   SELECT pg_catalog.setval('public.transaction_return_id_seq', 1, false);
          public          postgres    false    221            o           0    0    transaction_transaction_id_seq    SEQUENCE SET     M   SELECT pg_catalog.setval('public.transaction_transaction_id_seq', 1, false);
          public          postgres    false    216            p           0    0    transaction_user_id_seq    SEQUENCE SET     F   SELECT pg_catalog.setval('public.transaction_user_id_seq', 1, false);
          public          postgres    false    217            q           0    0    users_user_id_seq    SEQUENCE SET     ?   SELECT pg_catalog.setval('public.users_user_id_seq', 8, true);
          public          postgres    false    215            �           2606    16651    device device_pkey 
   CONSTRAINT     W   ALTER TABLE ONLY public.device
    ADD CONSTRAINT device_pkey PRIMARY KEY (device_id);
 <   ALTER TABLE ONLY public.device DROP CONSTRAINT device_pkey;
       public            postgres    false    231            �           2606    16642    loan_detail loan_detail_pkey 
   CONSTRAINT     _   ALTER TABLE ONLY public.loan_detail
    ADD CONSTRAINT loan_detail_pkey PRIMARY KEY (loan_id);
 F   ALTER TABLE ONLY public.loan_detail DROP CONSTRAINT loan_detail_pkey;
       public            postgres    false    223            �           2606    16640     return_detail return_detail_pkey 
   CONSTRAINT     e   ALTER TABLE ONLY public.return_detail
    ADD CONSTRAINT return_detail_pkey PRIMARY KEY (return_id);
 J   ALTER TABLE ONLY public.return_detail DROP CONSTRAINT return_detail_pkey;
       public            postgres    false    229            �           2606    16661    room room_pkey 
   CONSTRAINT     Q   ALTER TABLE ONLY public.room
    ADD CONSTRAINT room_pkey PRIMARY KEY (room_id);
 8   ALTER TABLE ONLY public.room DROP CONSTRAINT room_pkey;
       public            postgres    false    234            �           2606    16599    transaction transaction_pkey 
   CONSTRAINT     f   ALTER TABLE ONLY public.transaction
    ADD CONSTRAINT transaction_pkey PRIMARY KEY (transaction_id);
 F   ALTER TABLE ONLY public.transaction DROP CONSTRAINT transaction_pkey;
       public            postgres    false    219            �           2606    16581    users users_pkey 
   CONSTRAINT     S   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    214            �           2606    16702    loan_detail loan_device    FK CONSTRAINT     �   ALTER TABLE ONLY public.loan_detail
    ADD CONSTRAINT loan_device FOREIGN KEY (device_id) REFERENCES public.device(device_id) NOT VALID;
 A   ALTER TABLE ONLY public.loan_detail DROP CONSTRAINT loan_device;
       public          postgres    false    223    3231    231            �           2606    16697    loan_detail loan_transaction    FK CONSTRAINT     �   ALTER TABLE ONLY public.loan_detail
    ADD CONSTRAINT loan_transaction FOREIGN KEY (transaction_id) REFERENCES public.transaction(transaction_id) NOT VALID;
 F   ALTER TABLE ONLY public.loan_detail DROP CONSTRAINT loan_transaction;
       public          postgres    false    223    219    3225            �           2606    16692    return_detail return_device    FK CONSTRAINT     �   ALTER TABLE ONLY public.return_detail
    ADD CONSTRAINT return_device FOREIGN KEY (device_id) REFERENCES public.device(device_id) NOT VALID;
 E   ALTER TABLE ONLY public.return_detail DROP CONSTRAINT return_device;
       public          postgres    false    231    229    3231            �           2606    16687     return_detail return_transaction    FK CONSTRAINT     �   ALTER TABLE ONLY public.return_detail
    ADD CONSTRAINT return_transaction FOREIGN KEY (transaction_id) REFERENCES public.transaction(transaction_id) NOT VALID;
 J   ALTER TABLE ONLY public.return_detail DROP CONSTRAINT return_transaction;
       public          postgres    false    219    229    3225            �           2606    16682    room room_device    FK CONSTRAINT     �   ALTER TABLE ONLY public.room
    ADD CONSTRAINT room_device FOREIGN KEY (device_id) REFERENCES public.device(device_id) NOT VALID;
 :   ALTER TABLE ONLY public.room DROP CONSTRAINT room_device;
       public          postgres    false    234    231    3231            �           2606    16667    transaction transaction_device    FK CONSTRAINT     �   ALTER TABLE ONLY public.transaction
    ADD CONSTRAINT transaction_device FOREIGN KEY (device_id) REFERENCES public.device(device_id) NOT VALID;
 H   ALTER TABLE ONLY public.transaction DROP CONSTRAINT transaction_device;
       public          postgres    false    219    3231    231            �           2606    16672    transaction transaction_loan    FK CONSTRAINT     �   ALTER TABLE ONLY public.transaction
    ADD CONSTRAINT transaction_loan FOREIGN KEY (loan_id) REFERENCES public.loan_detail(loan_id) NOT VALID;
 F   ALTER TABLE ONLY public.transaction DROP CONSTRAINT transaction_loan;
       public          postgres    false    219    3227    223            �           2606    16677    transaction transaction_return    FK CONSTRAINT     �   ALTER TABLE ONLY public.transaction
    ADD CONSTRAINT transaction_return FOREIGN KEY (return_id) REFERENCES public.return_detail(return_id) NOT VALID;
 H   ALTER TABLE ONLY public.transaction DROP CONSTRAINT transaction_return;
       public          postgres    false    229    3229    219            �           2606    16662    transaction transaction_user    FK CONSTRAINT     �   ALTER TABLE ONLY public.transaction
    ADD CONSTRAINT transaction_user FOREIGN KEY (user_id) REFERENCES public.users(user_id) NOT VALID;
 F   ALTER TABLE ONLY public.transaction DROP CONSTRAINT transaction_user;
       public          postgres    false    219    214    3223            J      x������ � �      B      x������ � �      H      x������ � �      M      x������ � �      >      x������ � �      9   f   x���I-.1��% �!5713G/9?�S�(I��@�$�2��Ҽ�%��?=��0-��,=5�<  8Э2�8��#(��,9",�1�л�(�<#�31%73�+F��� n��     
"""empty message

Revision ID: da59e4cb00ab
Revises: 
Create Date: 2022-07-07 09:48:23.343140

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'da59e4cb00ab'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('departamento',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('grilla',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('codigoo', sa.String(length=100), nullable=False),
    sa.Column('codigo', sa.String(length=100), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=False),
    sa.Column('descripcion', sa.Text(), nullable=False),
    sa.Column('descripcion_abreviada', sa.Text(), nullable=False),
    sa.Column('puntaje', sa.Float(precision=5, asdecimal=3), nullable=False),
    sa.Column('unidad', sa.String(length=255), nullable=True),
    sa.Column('cantidad', sa.Float(precision=5, asdecimal=2), nullable=False),
    sa.Column('evento', sa.String(length=255), nullable=False),
    sa.Column('valor', sa.String(length=255), nullable=False),
    sa.Column('oculto', sa.Boolean(), nullable=False),
    sa.Column('grilla_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['grilla_id'], ['grilla.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('materia',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=False),
    sa.Column('descripcion', sa.String(length=255), nullable=False),
    sa.Column('estado', sa.String(length=255), nullable=False),
    sa.Column('fecha_alta', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('plan',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=False),
    sa.Column('descripcion', sa.String(length=255), nullable=False),
    sa.Column('resolucion', sa.String(length=255), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('role',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=True),
    sa.Column('default', sa.Boolean(), nullable=True),
    sa.Column('permissions', sa.Integer(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_role_default'), 'role', ['default'], unique=False)
    op.create_table('sala',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=False),
    sa.Column('descripcion', sa.String(length=255), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('tipoformacion',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=False),
    sa.Column('tipo_formacion_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['tipo_formacion_id'], ['tipoformacion.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('calificable',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('codigo', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=False),
    sa.Column('abreviatura', sa.String(length=255), nullable=False),
    sa.Column('sala_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['sala_id'], ['sala.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('formacion',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=False),
    sa.Column('resolucion', sa.String(length=255), nullable=False),
    sa.Column('horas', sa.Integer(), nullable=True),
    sa.Column('serie', sa.String(length=255), nullable=False),
    sa.Column('fecha', sa.DateTime(), nullable=True),
    sa.Column('departamento', sa.String(length=255), nullable=False),
    sa.Column('region', sa.String(length=255), nullable=False),
    sa.Column('ambito', sa.String(length=255), nullable=True),
    sa.Column('tipoformacion_id', sa.Integer(), nullable=True),
    sa.Column('grilla_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['grilla_id'], ['grilla.id'], ),
    sa.ForeignKeyConstraint(['tipoformacion_id'], ['tipoformacion.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('localidad',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=False),
    sa.Column('region', sa.String(length=255), nullable=False),
    sa.Column('ambito', sa.String(length=255), nullable=False),
    sa.Column('departamento_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['departamento_id'], ['departamento.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('materia_plan',
    sa.Column('materia_id', sa.Integer(), nullable=True),
    sa.Column('plan_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['materia_id'], ['materia.id'], ),
    sa.ForeignKeyConstraint(['plan_id'], ['plan.id'], )
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=True),
    sa.Column('email', sa.String(length=120), nullable=True),
    sa.Column('password_hash', sa.String(length=128), nullable=True),
    sa.Column('about_me', sa.String(length=140), nullable=True),
    sa.Column('last_seen', sa.DateTime(), nullable=True),
    sa.Column('token', sa.String(length=32), nullable=True),
    sa.Column('token_expiration', sa.DateTime(), nullable=True),
    sa.Column('role_id', sa.Integer(), nullable=True),
    sa.Column('last_message_read_time', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['role_id'], ['role.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_email'), 'user', ['email'], unique=True)
    op.create_index(op.f('ix_user_token'), 'user', ['token'], unique=True)
    op.create_index(op.f('ix_user_username'), 'user', ['username'], unique=True)
    op.create_table('agente',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=True),
    sa.Column('apellido', sa.String(length=120), nullable=True),
    sa.Column('dni', sa.Integer(), nullable=True),
    sa.Column('cuil', sa.BigInteger(), nullable=True),
    sa.Column('nacionalidad', sa.String(length=255), nullable=True),
    sa.Column('domicilio', sa.String(length=255), nullable=True),
    sa.Column('fechanac', sa.DateTime(), nullable=True),
    sa.Column('telefono', sa.String(length=100), nullable=True),
    sa.Column('caracter', sa.String(length=255), nullable=True),
    sa.Column('estadocivil', sa.String(length=255), nullable=True),
    sa.Column('celular', sa.String(length=255), nullable=True),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('localidad_id', sa.Integer(), nullable=True),
    sa.Column('last_message_read_time', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['localidad_id'], ['localidad.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('dni'),
    sa.UniqueConstraint('email')
    )
    op.create_index(op.f('ix_agente_apellido'), 'agente', ['apellido'], unique=False)
    op.create_index(op.f('ix_agente_nombre'), 'agente', ['nombre'], unique=False)
    op.create_table('competencia',
    sa.Column('codigo', sa.String(length=255), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.Column('materia_id', sa.Integer(), nullable=True),
    sa.Column('formacion_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['formacion_id'], ['formacion.id'], ),
    sa.ForeignKeyConstraint(['materia_id'], ['materia.id'], )
    )
    op.create_table('followers',
    sa.Column('follower_id', sa.Integer(), nullable=True),
    sa.Column('followed_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['followed_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['follower_id'], ['user.id'], )
    )
    op.create_table('institucion',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('nombre', sa.String(length=255), nullable=False),
    sa.Column('cueanexo', sa.Integer(), nullable=False),
    sa.Column('domicilio', sa.String(length=255), nullable=True),
    sa.Column('localidad', sa.String(length=255), nullable=False),
    sa.Column('departamento', sa.String(length=255), nullable=False),
    sa.Column('region', sa.String(length=255), nullable=False),
    sa.Column('ambito', sa.String(length=255), nullable=True),
    sa.Column('localidad_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['localidad_id'], ['localidad.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('message',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('sender_id', sa.Integer(), nullable=True),
    sa.Column('recipient_id', sa.Integer(), nullable=True),
    sa.Column('body', sa.String(length=140), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['recipient_id'], ['user.id'], ),
    sa.ForeignKeyConstraint(['sender_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_message_timestamp'), 'message', ['timestamp'], unique=False)
    op.create_table('notification',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('timestamp', sa.Float(), nullable=True),
    sa.Column('payload_json', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_notification_name'), 'notification', ['name'], unique=False)
    op.create_index(op.f('ix_notification_timestamp'), 'notification', ['timestamp'], unique=False)
    op.create_table('post',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('body', sa.String(length=140), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('language', sa.String(length=5), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_post_timestamp'), 'post', ['timestamp'], unique=False)
    op.create_table('task',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=True),
    sa.Column('description', sa.String(length=128), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('complete', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_task_name'), 'task', ['name'], unique=False)
    op.create_table('legajo',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('codigo', sa.String(length=255), nullable=False),
    sa.Column('agente_id', sa.Integer(), nullable=True),
    sa.Column('calificable_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['agente_id'], ['agente.id'], ),
    sa.ForeignKeyConstraint(['calificable_id'], ['calificable.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('titulo',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('titulo', sa.String(length=255), nullable=False),
    sa.Column('orientacion', sa.String(length=255), nullable=True),
    sa.Column('carrera', sa.String(length=255), nullable=True),
    sa.Column('resolucion', sa.String(length=255), nullable=True),
    sa.Column('modalidad', sa.String(length=255), nullable=False),
    sa.Column('institucion_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['institucion_id'], ['institucion.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('antecedente',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('cantidad', sa.Float(precision=5, asdecimal=2), nullable=False),
    sa.Column('valor', sa.Float(precision=4, asdecimal=2), nullable=False),
    sa.Column('descripcion', sa.Text(), nullable=False),
    sa.Column('codigo', sa.String(length=255), nullable=False),
    sa.Column('legajo_id', sa.Integer(), nullable=True),
    sa.Column('grilla_id', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('egreso', sa.DateTime(), nullable=True),
    sa.Column('registro', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['grilla_id'], ['grilla.id'], ),
    sa.ForeignKeyConstraint(['legajo_id'], ['legajo.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('titulo_user',
    sa.Column('titulo_id', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['titulo_id'], ['titulo.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], )
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('titulo_user')
    op.drop_table('antecedente')
    op.drop_table('titulo')
    op.drop_table('legajo')
    op.drop_index(op.f('ix_task_name'), table_name='task')
    op.drop_table('task')
    op.drop_index(op.f('ix_post_timestamp'), table_name='post')
    op.drop_table('post')
    op.drop_index(op.f('ix_notification_timestamp'), table_name='notification')
    op.drop_index(op.f('ix_notification_name'), table_name='notification')
    op.drop_table('notification')
    op.drop_index(op.f('ix_message_timestamp'), table_name='message')
    op.drop_table('message')
    op.drop_table('institucion')
    op.drop_table('followers')
    op.drop_table('competencia')
    op.drop_index(op.f('ix_agente_nombre'), table_name='agente')
    op.drop_index(op.f('ix_agente_apellido'), table_name='agente')
    op.drop_table('agente')
    op.drop_index(op.f('ix_user_username'), table_name='user')
    op.drop_index(op.f('ix_user_token'), table_name='user')
    op.drop_index(op.f('ix_user_email'), table_name='user')
    op.drop_table('user')
    op.drop_table('materia_plan')
    op.drop_table('localidad')
    op.drop_table('formacion')
    op.drop_table('calificable')
    op.drop_table('tipoformacion')
    op.drop_table('sala')
    op.drop_index(op.f('ix_role_default'), table_name='role')
    op.drop_table('role')
    op.drop_table('plan')
    op.drop_table('materia')
    op.drop_table('grilla')
    op.drop_table('departamento')
    # ### end Alembic commands ###

-- =====================================================
-- ARENA ROMA — RPCs v1 + Policies
-- Tudo que o frontend precisa pra operar via anon key
-- =====================================================

-- VIEW pública de admins (sem expor senha_hash)
CREATE OR REPLACE VIEW admins_pub AS
  SELECT id, nome, cpf, role, ativo, last_login, created_at FROM admins;

-- =====================================================
-- POLICIES — SELECT permissivo via anon (read-only)
-- INSERT/UPDATE/DELETE somente via RPC SECURITY DEFINER
-- =====================================================
DROP POLICY IF EXISTS p_vendedores_read ON vendedores;
CREATE POLICY p_vendedores_read ON vendedores FOR SELECT TO anon, authenticated USING (true);

DROP POLICY IF EXISTS p_campanhas_read ON campanhas;
CREATE POLICY p_campanhas_read ON campanhas FOR SELECT TO anon, authenticated USING (true);

DROP POLICY IF EXISTS p_premios_read ON premios;
CREATE POLICY p_premios_read ON premios FOR SELECT TO anon, authenticated USING (true);

DROP POLICY IF EXISTS p_resgates_read ON resgates;
CREATE POLICY p_resgates_read ON resgates FOR SELECT TO anon, authenticated USING (true);

DROP POLICY IF EXISTS p_hist_read ON historico_pontos;
CREATE POLICY p_hist_read ON historico_pontos FOR SELECT TO anon, authenticated USING (true);

-- admins: SELECT bloqueado pra anon (usa view admins_pub)
-- Já tem RLS habilitado, sem policy = nada lê.
-- Mas a view admins_pub precisa de grant
GRANT SELECT ON admins_pub TO anon, authenticated;

-- =====================================================
-- RPC: criar_vendedor
-- =====================================================
CREATE OR REPLACE FUNCTION criar_vendedor(
  _nome text, _cpf text, _loja text, _grupo text, _supervisora text,
  _whatsapp text, _senha text, _admin_cpf text DEFAULT NULL
) RETURNS TABLE (id uuid, nome text, cpf text, loja text, grupo text) AS $$
DECLARE
  v_id uuid;
  a_id uuid;
BEGIN
  -- Pega o admin que tá criando (pra log)
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;

  INSERT INTO vendedores (nome, cpf, senha_hash, loja, grupo, supervisora, whatsapp, pontos, status)
  VALUES (_nome, _cpf, crypt(_senha, gen_salt('bf')), _loja, _grupo, _supervisora, _whatsapp, 0, 'ativo')
  RETURNING vendedores.id INTO v_id;

  INSERT INTO historico_pontos (vendedor_id, delta, motivo, origem, admin_id)
  VALUES (v_id, 0, 'Cadastro inicial', 'cadastro', a_id);

  RETURN QUERY SELECT v.id, v.nome, v.cpf, v.loja, v.grupo FROM vendedores v WHERE v.id = v_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: ajustar_pontos_manual
-- =====================================================
CREATE OR REPLACE FUNCTION ajustar_pontos_manual(
  _vendedor_id uuid, _delta int, _motivo text, _admin_cpf text
) RETURNS TABLE (vendedor_id uuid, pontos_novos int) AS $$
DECLARE
  a_id uuid;
  p_novo int;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;

  UPDATE vendedores SET pontos = GREATEST(0, pontos + _delta)
  WHERE id = _vendedor_id RETURNING pontos INTO p_novo;

  INSERT INTO historico_pontos (vendedor_id, delta, motivo, origem, admin_id)
  VALUES (_vendedor_id, _delta, _motivo, 'manual', a_id);

  RETURN QUERY SELECT _vendedor_id, p_novo;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: importar_pontos_csv (recebe JSON array)
-- Formato: [{"vendedor_id":"uuid","delta":10},...]
-- =====================================================
CREATE OR REPLACE FUNCTION importar_pontos_csv(
  _registros jsonb, _arquivo text, _admin_cpf text
) RETURNS TABLE (aplicados int, total_pontos int) AS $$
DECLARE
  a_id uuid;
  r jsonb;
  v_id uuid;
  v_delta int;
  qtd int := 0;
  soma int := 0;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;

  FOR r IN SELECT * FROM jsonb_array_elements(_registros) LOOP
    v_id := (r->>'vendedor_id')::uuid;
    v_delta := (r->>'delta')::int;
    IF v_id IS NULL OR v_delta IS NULL OR v_delta = 0 THEN CONTINUE; END IF;

    UPDATE vendedores SET pontos = GREATEST(0, pontos + v_delta) WHERE id = v_id;
    INSERT INTO historico_pontos (vendedor_id, delta, motivo, origem, admin_id)
    VALUES (v_id, v_delta, 'Importação: ' || _arquivo, 'import', a_id);

    qtd := qtd + 1;
    soma := soma + v_delta;
  END LOOP;

  RETURN QUERY SELECT qtd, soma;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: pedir_resgate (vendedor pede troca de pontos)
-- =====================================================
CREATE OR REPLACE FUNCTION pedir_resgate(
  _vendedor_cpf text, _premio_id uuid
) RETURNS TABLE (resgate_id uuid, status text) AS $$
DECLARE
  v_id uuid;
  v_pts int;
  p_custo int;
  r_id uuid;
BEGIN
  SELECT id, pontos INTO v_id, v_pts FROM vendedores WHERE cpf = _vendedor_cpf AND status = 'ativo';
  IF v_id IS NULL THEN RAISE EXCEPTION 'Vendedor não encontrado'; END IF;

  SELECT custo_pts INTO p_custo FROM premios WHERE id = _premio_id AND ativo = true;
  IF p_custo IS NULL THEN RAISE EXCEPTION 'Prêmio inválido'; END IF;
  IF v_pts < p_custo THEN RAISE EXCEPTION 'Pontos insuficientes (% de %)', v_pts, p_custo; END IF;

  INSERT INTO resgates (vendedor_id, premio_id, custo_pts, status)
  VALUES (v_id, _premio_id, p_custo, 'pending')
  RETURNING id INTO r_id;

  RETURN QUERY SELECT r_id, 'pending'::text;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: aprovar_resgate
-- =====================================================
CREATE OR REPLACE FUNCTION aprovar_resgate(
  _resgate_id uuid, _admin_cpf text
) RETURNS TABLE (ok boolean, pontos_finais int) AS $$
DECLARE
  a_id uuid;
  r record;
  p_final int;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;

  SELECT * INTO r FROM resgates WHERE id = _resgate_id AND status = 'pending';
  IF NOT FOUND THEN RAISE EXCEPTION 'Resgate não encontrado ou já processado'; END IF;

  UPDATE vendedores SET pontos = GREATEST(0, pontos - r.custo_pts)
  WHERE id = r.vendedor_id RETURNING pontos INTO p_final;

  UPDATE resgates SET status = 'approved', aprovado_por = a_id, aprovado_em = now()
  WHERE id = _resgate_id;

  INSERT INTO historico_pontos (vendedor_id, delta, motivo, origem, referencia_id, admin_id)
  VALUES (r.vendedor_id, -r.custo_pts,
    'Resgate aprovado (' || (SELECT titulo FROM premios WHERE id = r.premio_id) || ')',
    'resgate', _resgate_id, a_id);

  -- decrementa estoque se aplicável
  UPDATE premios SET estoque = estoque - 1
  WHERE id = r.premio_id AND estoque IS NOT NULL AND estoque > 0;

  RETURN QUERY SELECT true, p_final;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: recusar_resgate
-- =====================================================
CREATE OR REPLACE FUNCTION recusar_resgate(
  _resgate_id uuid, _admin_cpf text, _motivo text DEFAULT NULL
) RETURNS boolean AS $$
DECLARE
  a_id uuid;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;

  UPDATE resgates SET status = 'rejected', aprovado_por = a_id, aprovado_em = now(), observacao = _motivo
  WHERE id = _resgate_id AND status = 'pending';

  RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: salvar_campanha (insert ou update)
-- =====================================================
CREATE OR REPLACE FUNCTION salvar_campanha(
  _id uuid, _titulo text, _desc text, _tipo text, _acesso text,
  _inicio date, _fim date, _premio text, _status text, _admin_cpf text
) RETURNS uuid AS $$
DECLARE
  a_id uuid;
  c_id uuid;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;

  IF _id IS NULL THEN
    INSERT INTO campanhas (titulo, descricao, tipo, regra_acesso, inicio, fim, premio, status, criado_por)
    VALUES (_titulo, _desc, _tipo, _acesso, _inicio, _fim, _premio, _status, a_id)
    RETURNING id INTO c_id;
  ELSE
    UPDATE campanhas SET
      titulo = _titulo, descricao = _desc, tipo = _tipo, regra_acesso = _acesso,
      inicio = _inicio, fim = _fim, premio = _premio, status = _status
    WHERE id = _id
    RETURNING id INTO c_id;
  END IF;

  RETURN c_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: excluir_campanha
-- =====================================================
CREATE OR REPLACE FUNCTION excluir_campanha(_id uuid, _admin_cpf text) RETURNS boolean AS $$
DECLARE a_id uuid;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;
  DELETE FROM campanhas WHERE id = _id;
  RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: salvar_premio (insert ou update)
-- =====================================================
CREATE OR REPLACE FUNCTION salvar_premio(
  _id uuid, _icone text, _titulo text, _desc text, _custo_pts int, _estoque int, _ativo boolean,
  _admin_cpf text
) RETURNS uuid AS $$
DECLARE
  a_id uuid;
  p_id uuid;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;

  IF _id IS NULL THEN
    INSERT INTO premios (icone, titulo, descricao, custo_pts, estoque, ativo)
    VALUES (_icone, _titulo, _desc, _custo_pts, _estoque, _ativo) RETURNING id INTO p_id;
  ELSE
    UPDATE premios SET icone=_icone, titulo=_titulo, descricao=_desc, custo_pts=_custo_pts, estoque=_estoque, ativo=_ativo
    WHERE id = _id RETURNING id INTO p_id;
  END IF;
  RETURN p_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: excluir_premio
-- =====================================================
CREATE OR REPLACE FUNCTION excluir_premio(_id uuid, _admin_cpf text) RETURNS boolean AS $$
DECLARE a_id uuid;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;
  UPDATE premios SET ativo = false WHERE id = _id;  -- soft delete
  RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: criar_admin (Mariana/Dara podem cadastrar mais admins)
-- =====================================================
CREATE OR REPLACE FUNCTION criar_admin(
  _nome text, _cpf text, _senha text, _role text, _admin_cpf text
) RETURNS uuid AS $$
DECLARE
  a_id uuid;
  novo_id uuid;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;

  INSERT INTO admins (nome, cpf, senha_hash, role, ativo)
  VALUES (_nome, _cpf, crypt(_senha, gen_salt('bf')), _role, true)
  RETURNING id INTO novo_id;
  RETURN novo_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: resetar_senha_admin
-- =====================================================
CREATE OR REPLACE FUNCTION resetar_senha_admin(
  _target_cpf text, _nova_senha text, _admin_cpf text
) RETURNS boolean AS $$
DECLARE a_id uuid;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;
  UPDATE admins SET senha_hash = crypt(_nova_senha, gen_salt('bf')) WHERE cpf = _target_cpf;
  RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: resetar_senha_vendedor
-- =====================================================
CREATE OR REPLACE FUNCTION resetar_senha_vendedor(
  _target_cpf text, _nova_senha text, _admin_cpf text
) RETURNS boolean AS $$
DECLARE a_id uuid;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;
  UPDATE vendedores SET senha_hash = crypt(_nova_senha, gen_salt('bf')) WHERE cpf = _target_cpf;
  RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- RPC: desativar_vendedor (soft delete)
-- =====================================================
CREATE OR REPLACE FUNCTION desativar_vendedor(_vendedor_id uuid, _admin_cpf text) RETURNS boolean AS $$
DECLARE a_id uuid;
BEGIN
  SELECT a.id INTO a_id FROM admins a WHERE a.cpf = _admin_cpf AND a.ativo = true;
  IF a_id IS NULL THEN RAISE EXCEPTION 'Admin inválido'; END IF;
  UPDATE vendedores SET status = 'inativo' WHERE id = _vendedor_id;
  RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =====================================================
-- GRANTS pras RPCs serem chamáveis por anon
-- =====================================================
GRANT EXECUTE ON FUNCTION login_admin(text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION login_vendedor(text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION criar_vendedor(text, text, text, text, text, text, text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION ajustar_pontos_manual(uuid, int, text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION importar_pontos_csv(jsonb, text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION pedir_resgate(text, uuid) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION aprovar_resgate(uuid, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION recusar_resgate(uuid, text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION salvar_campanha(uuid, text, text, text, text, date, date, text, text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION excluir_campanha(uuid, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION salvar_premio(uuid, text, text, text, int, int, boolean, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION excluir_premio(uuid, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION criar_admin(text, text, text, text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION resetar_senha_admin(text, text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION resetar_senha_vendedor(text, text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION desativar_vendedor(uuid, text) TO anon, authenticated;
